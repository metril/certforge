import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { useState } from 'react';
import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { DnsCredential, IssuanceDefaults } from '@/api/types';
import { account, ca, caLocal, makeClient } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { EffectiveConfigList } from '@/features/certificates/detail/shared';
import { builtinStateOf, chainFor, effectiveText, fieldFromTitle, fromBuiltin, fromDefault, fromEffective, fullPayload, IssuanceDefaultsForm, ISSUANCE_FIELDS, rulesSummary, type FieldCtx, type FormProps } from './issuanceFields';

const ctx: FieldCtx = { cas: [], accounts: [], credentials: [], clients: [] };
const renewPolicy = ISSUANCE_FIELDS.find((f) => f.key === 'renewPolicy')!;
const caField = ISSUANCE_FIELDS.find((f) => f.key === 'caId')!;
const accountField = ISSUANCE_FIELDS.find((f) => f.key === 'accountId')!;
const verificationRulesField = ISSUANCE_FIELDS.find((f) => f.key === 'verificationRules')!;

describe('renewPolicy copy (preflight A9: value is percent of lifetime REMAINING)', () => {
  it('shows the percent copy as "remains", not "elapsed"', () => {
    expect(renewPolicy.display({ mode: 'percent', value: 33, useAri: false }, ctx)).toBe('When 33% of the lifetime remains');
  });
  it('shows the days copy', () => {
    expect(renewPolicy.display({ mode: 'days', value: 30, useAri: false }, ctx)).toBe('30 days before expiry');
  });
  it('appends ARI when on', () => {
    expect(renewPolicy.display({ mode: 'percent', value: 33, useAri: true }, ctx)).toBe('When 33% of the lifetime remains, ARI on');
  });
  it('defaults to the built-in policy (BuiltinDefaults(): percent, 33)', () => {
    expect(renewPolicy.initial(ctx)).toEqual({ mode: 'percent', value: 33, useAri: false });
  });
});

describe('fromDefault / fromEffective', () => {
  it('fromDefault is always source default with a null value', () => {
    expect(fromDefault()).toEqual({ value: null, source: 'default' });
  });
  it('fromEffective looks up the field and falls back to default when absent', () => {
    const eff = { keyType: { value: 'rsa2048', source: 'org' } } as never;
    expect(fromEffective(eff)('keyType')).toEqual({ value: 'rsa2048', source: 'org' });
    expect(fromEffective(eff)('caId')).toEqual({ value: null, source: 'default' });
  });
});

describe('fieldFromTitle (a 422 title is always "Invalid <field>")', () => {
  it.each([
    ['Invalid caId', 'caId'],
    ['Invalid accountId', 'accountId'],
    ['Invalid renewPolicy.value', 'renewPolicy'],
    ['Invalid renewPolicy.mode', 'renewPolicy'],
    ['Invalid propagationSeconds', 'propagationSeconds'],
    ['Invalid verificationRules', 'verificationRules'],
    ['Something else', null],
  ])('%s -> %s', (title, field) => {
    expect(fieldFromTitle(title)).toBe(field);
  });
});

describe('fromBuiltin (review fix round 1, #1)', () => {
  it('is always source default, with the built-in value for display', () => {
    expect(fromBuiltin({ keyType: 'ec256' })('keyType')).toEqual({ value: 'ec256', source: 'default' });
  });
  it('falls back to null when the built-in value itself is absent', () => {
    expect(fromBuiltin({})('caId')).toEqual({ value: null, source: 'default' });
  });
});

describe('fullPayload (review fix round 1, #1/#3)', () => {
  it('sends every field explicitly: the given value, or null for one that is absent', () => {
    expect(fullPayload({ keyType: 'rsa2048' })).toEqual({
      caId: null,
      accountId: null,
      keyType: 'rsa2048',
      renewPolicy: null,
      preferredChain: null,
      reuseKey: null,
      mustStaple: null,
      propagationSeconds: null,
      resolvers: null,
      // Task 13: verificationRules now has its own ISSUANCE_FIELDS entry
      // (VerificationRulesEditor), so it's sent explicitly like every
      // other field rather than only surviving via the spread below.
      verificationRules: null,
    });
  });

  // Review fix round 2: a key this page doesn't render has no ISSUANCE_FIELDS
  // entry, so the old Object.fromEntries-only build dropped it — a "replace
  // the whole object" PUT would then delete a stored-but-unrendered section
  // on any unrelated save. verificationRules itself gained an entry in Task
  // 13 (see the explicit-null case above), so a value it doesn't know about
  // stands in here for "anything added later that this page still doesn't render".
  it('passes an unrendered key through untouched', () => {
    const value = { keyType: 'rsa2048' as const, ...({ someFutureField: 'x' } as Record<string, unknown>) } as Parameters<typeof fullPayload>[0];
    expect(fullPayload(value)).toEqual(expect.objectContaining({ keyType: 'rsa2048', someFutureField: 'x' }));
  });
});

describe('lookup fields disable Override when there is nothing to choose (review fix round 1, #4)', () => {
  it('caId', () => {
    expect(caField.disabledReason?.(ctx)).toBe('No CAs yet');
    expect(caField.disabledReason?.({ ...ctx, cas: [{ ...ca, name: 'x', directoryUrl: '' }] })).toBeUndefined();
  });
  it('accountId', () => {
    expect(accountField.disabledReason?.(ctx)).toBe('No accounts yet');
  });
});

describe('rulesSummary (Task 3: per-rule methods, never "no credential" for HTTP/TLS-ALPN)', () => {
  const creds: DnsCredential[] = [{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }];
  const clients = [makeClient({ id: 'c-1', name: 'web-1', status: 'active', capabilities: ['http-01', 'tls-alpn-01'] })];

  it('names server or a client for HTTP/TLS-ALPN, and manual for manual-dns', () => {
    expect(
      rulesSummary(
        [
          { match: 'a.test', method: 'dns-01', dnsCredentialId: 'd-1' },
          { match: 'b.test', method: 'http-01', via: 'server' },
          { match: 'c.test', method: 'http-01', via: 'agent', clientId: 'c-1' },
          { match: 'd.test', method: 'tls-alpn-01', clientId: 'c-1' },
          { match: 'e.test', method: 'manual-dns' },
        ],
        creds,
        clients,
      ),
    ).toBe('a.test → Cloudflare prod; b.test → server; c.test → web-1; d.test → web-1; e.test → manual');
  });

  it('an agent rule with no client says "no client", never "no credential"', () => {
    expect(rulesSummary([{ match: 'a.test', method: 'tls-alpn-01' }], creds, clients)).toBe('a.test → no client');
  });
});

// Task 3 (B1): the Global tab's issuance defaults aren't org-scoped, so its
// verification-rules editor's TLS-ALPN client picker offers no clients.
describe('the Global tab has no clients (FieldCtx.clients: [] there)', () => {
  it('a TLS-ALPN row shows the empty text instead of any client', async () => {
    const { user } = renderUI(<>{verificationRulesField.editor([{ match: '*', method: 'tls-alpn-01' }], () => {}, { ...ctx, clients: [] }, 'f-verificationRules')}</>);
    await user.click(screen.getByRole('combobox', { name: 'Rule 1 client' }));
    expect(await screen.findByText('No client serves tls-alpn-01')).toBeInTheDocument();
    expect(screen.queryByRole('option')).toBeNull();
  });

  // Review fix round 1 (Important): IssuanceDefaultsSection's globalCtx now
  // also sets agentModes: false, since an empty client list alone still let
  // TLS-ALPN/Served-by-Agent be picked in the Global context and 422 on
  // Save — the field editor must thread FieldCtx.agentModes through.
  it('TLS-ALPN and Served by Agent are disabled when the context sets agentModes: false', async () => {
    const globalCtx: FieldCtx = { ...ctx, clients: [], agentModes: false };
    const { user } = renderUI(<>{verificationRulesField.editor([{ match: '*', method: 'http-01', via: 'server' }], () => {}, globalCtx, 'f-verificationRules')}</>);
    const tlsAlpn = screen.getByRole('radio', { name: 'TLS-ALPN' });
    expect(tlsAlpn).toBeDisabled();
    const agent = screen.getByRole('radio', { name: 'Agent' });
    expect(agent).toBeDisabled();
    await user.hover(agent);
    expect(await screen.findByRole('tooltip')).toHaveTextContent(/agent methods need an org/i);
  });
});

// Task 4 (R12 deviation): the account field is disabled for a private
// effective CA — computed by IssuanceDefaultsForm itself from `value`/
// `inherited`/`ctx.cas`, not a caller-supplied flag, so it works the same
// in the wizard's Options step and in Settings' issuance defaults.
describe('IssuanceDefaultsForm disables the account field for a private effective CA', () => {
  const emptyEff = { value: null, source: 'default' as const };
  const inherited = () => emptyEff;

  function H({ initial }: { initial: IssuanceDefaults }) {
    const [value, setValue] = useState<IssuanceDefaults>(initial);
    return <IssuanceDefaultsForm value={value} onChange={setValue} inherited={inherited} ctx={{ ...ctx, cas: [ca, caLocal], accounts: [account] }} />;
  }

  it('account disabled for private CA', async () => {
    const { user } = renderUI(<H initial={{ caId: caLocal.id }} />);
    const accountSwitch = screen.getByRole('switch', { name: 'Override ACME account' });
    expect(accountSwitch).toBeDisabled();
    expect(screen.getByText('Not used by private CAs')).toBeInTheDocument();
    const group = screen.getByRole('group', { name: 'ACME account' });
    await user.hover(within(group).getByRole('button', { name: 'Help' }));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('ACME accounts do not apply to private CAs.');
  });

  it('an acme effective CA leaves the account field enabled', () => {
    renderUI(<H initial={{ caId: ca.id }} />);
    expect(screen.getByRole('switch', { name: 'Override ACME account' })).not.toBeDisabled();
  });

  it('choosing private CA clears account override', async () => {
    const { user } = renderUI(<H initial={{ caId: ca.id, accountId: 'acc-1' }} />);
    expect(screen.getByRole('switch', { name: 'Override ACME account' })).toBeChecked();
    await user.click(screen.getByRole('combobox', { name: 'Certificate authority' }));
    await user.click(await screen.findByText(caLocal.name));
    expect(screen.getByRole('switch', { name: 'Override ACME account' })).not.toBeChecked();
    expect(screen.getByRole('switch', { name: 'Override ACME account' })).toBeDisabled();
  });

  // Batch 2 review (Minor): a certificate can be loaded (e.g. into the
  // wizard's edit route) with an accountId override but no caId override,
  // where the *inherited* default CA already happens to be private —
  // saving unchanged used to still send the stale accountId and 422
  // ("account belongs to a different CA"). Clearing on the caId field's own
  // onChange (the test above) never fires here, since caId is never
  // touched — the form must reconcile this on its own once it sees the
  // combination on render.
  it('clears an existing account override at init for an already-private inherited CA', () => {
    const inheritedPrivate = (k: Parameters<FormProps['inherited']>[0]) => (k === 'caId' ? { value: caLocal.id, source: 'org' as const } : emptyEff);
    function HInit() {
      const [value, setValue] = useState<IssuanceDefaults>({ accountId: 'acc-1' });
      return <IssuanceDefaultsForm value={value} onChange={setValue} inherited={inheritedPrivate} ctx={{ ...ctx, cas: [ca, caLocal], accounts: [account] }} />;
    }
    renderUI(<HInit />);
    expect(screen.getByRole('switch', { name: 'Override ACME account' })).not.toBeChecked();
  });
});

describe('editor widths (review fix round 1, #8: no fixed width that overflows a 375px viewport)', () => {
  it('never uses a bare w-72/w-96 class — every editor wrapper is w-full max-w-96', () => {
    const src = readFileSync(resolve(import.meta.dirname, './issuanceFields.tsx'), 'utf8');
    expect(src).not.toMatch(/className="w-72/);
    expect(src).not.toMatch(/className="w-96/);
  });
});

describe('IssuanceDefaultsForm sections', () => {
  const inherited = () => ({ value: null, source: 'default' as const });

  function H({ initial }: { initial: IssuanceDefaults }) {
    const [value, setValue] = useState<IssuanceDefaults>(initial);
    return <IssuanceDefaultsForm value={value} onChange={setValue} inherited={inherited} ctx={ctx} />;
  }

  it('groups fields into Issuer, Keys and renewal and Verification', () => {
    renderUI(<H initial={{}} />);
    for (const t of ['Issuer', 'Keys and renewal', 'Verification']) expect(screen.getByRole('heading', { name: t })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Reset section/ })).not.toBeInTheDocument();
  });

  it('shows N overridden and resets only that section', async () => {
    const { user } = renderUI(<H initial={{ keyType: 'rsa2048', reuseKey: true, propagationSeconds: 60 }} />);
    const keys = screen.getByRole('region', { name: 'Keys and renewal' });
    expect(within(keys).getByText(/2 overridden/)).toBeInTheDocument();
    await user.click(within(keys).getByRole('button', { name: 'Reset section Keys and renewal' }));
    expect(within(keys).queryByText(/overridden/)).not.toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Verification' })).getByText(/1 overridden/)).toBeInTheDocument();
  });
});

// While the server's built-in defaults are unknown nothing built-in is shown:
// no "not set" wording.
describe('unknown shipped defaults', () => {
  const unset = 'none — issuance fails until one is set';
  const Form = ({ state }: { state?: 'loading' | 'error' }) => (
    <IssuanceDefaultsForm value={{}} onChange={() => {}} inherited={fromBuiltin(undefined)} chain={chainFor(undefined, {}, undefined, ctx)} builtinState={state} level="global" ctx={ctx} />
  );
  it('loading shows a skeleton, never the unset wording', () => {
    renderUI(<Form state="loading" />);
    expect(screen.getAllByRole('status', { name: 'Loading default' }).length).toBeGreaterThan(0);
    expect(screen.queryByText(unset)).toBeNull();
    expect(screen.queryByText('not set')).toBeNull();
  });
  it('an error says the value is unavailable', () => {
    renderUI(<Form state="error" />);
    expect(screen.getAllByText('Default unavailable').length).toBeGreaterThan(0);
    expect(screen.queryByText(unset)).toBeNull();
  });
  it('a served null built-in still shows the unset wording', () => {
    renderUI(<IssuanceDefaultsForm value={{}} onChange={() => {}} inherited={fromBuiltin({})} chain={chainFor({}, {}, undefined, ctx)} level="global" ctx={ctx} />);
    expect(screen.getAllByText(unset).length).toBeGreaterThan(0);
  });
  it('builtinStateOf: loading, failed, a response without builtin, known', () => {
    expect(builtinStateOf({ data: undefined })).toBe('loading');
    expect(builtinStateOf({ data: undefined, isError: true })).toBe('error');
    expect(builtinStateOf({ data: {} })).toBe('error');
    expect(builtinStateOf({ data: { builtin: {} } })).toBeUndefined();
  });
});

describe('propagation wait with nothing set (API reports 0, source default)', () => {
  const unsetEff = { propagationSeconds: { value: 0, source: 'default' } } as never;
  const setEff = { propagationSeconds: { value: 0, source: 'org' } } as never;
  const prop = ISSUANCE_FIELDS.find((f) => f.key === 'propagationSeconds')!;
  const OrgForm = ({ eff }: { eff: never }) => (
    <IssuanceDefaultsForm value={{}} onChange={() => {}} inherited={fromEffective(eff)} level="org" ctx={ctx} />
  );
  it('org scope reads as the DNS provider timeout, not 0 s', () => {
    renderUI(<OrgForm eff={unsetEff} />);
    expect(screen.getByText("the DNS provider's own timeout")).toBeInTheDocument();
    expect(screen.queryByText('0 s')).toBeNull();
  });
  it('org scope shows an explicit 0 as 0 s', () => {
    renderUI(<OrgForm eff={setEff} />);
    expect(screen.getByText('0 s')).toBeInTheDocument();
  });
  it('certificate detail effective configuration follows the same rule', () => {
    const { unmount } = renderUI(<EffectiveConfigList eff={unsetEff} ctx={ctx} />);
    expect(screen.getByText("the DNS provider's own timeout")).toBeInTheDocument();
    unmount();
    renderUI(<EffectiveConfigList eff={setEff} ctx={ctx} />);
    expect(screen.getByText('0 s')).toBeInTheDocument();
  });
  it('wizard summary/review text (effectiveText) follows the same rule', () => {
    expect(effectiveText(prop, { value: 0, source: 'default' }, ctx)).toBe("the DNS provider's own timeout");
    expect(effectiveText(prop, { value: 0, source: 'cert' }, ctx)).toBe('0 s');
    expect(effectiveText(prop, { value: 90, source: 'global' }, ctx)).toBe('90 s');
  });
});
