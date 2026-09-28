import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { DnsCredential } from '@/api/types';
import { ca, makeClient } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { fieldFromTitle, fromBuiltin, fromDefault, fromEffective, fullPayload, ISSUANCE_FIELDS, rulesSummary, type FieldCtx } from './issuanceFields';

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

describe('editor widths (review fix round 1, #8: no fixed width that overflows a 375px viewport)', () => {
  it('never uses a bare w-72/w-96 class — every editor wrapper is w-full max-w-96', () => {
    const src = readFileSync(resolve(import.meta.dirname, './issuanceFields.tsx'), 'utf8');
    expect(src).not.toMatch(/className="w-72/);
    expect(src).not.toMatch(/className="w-96/);
  });
});
