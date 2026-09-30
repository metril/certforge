import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleCheck, CircleX } from 'lucide-react';
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { keysStatusQuery } from '@/api/queries/keys';
import { testVault } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import type { VaultSettings, VaultTestResult } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { fieldErrorFromMessage } from '@/forms/uiSchema';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { PrometheusScrape } from './PrometheusScrape';
import { SchemaSection } from './SchemaSection';
import { SmtpTest } from './SmtpTest';

// authMethod drives which secret field is actually usable: a token
// exchanged for approle (or vice versa) is never sent, so the unused pair
// is hidden with the same `ui:widget: 'hidden'` mechanism uiSchema.ts's
// buildUiSchema already uses for server-derived fields — no label, no
// input, and FieldTemplate's own `hidden` short-circuit skips both. The
// segmented control's own tooltip is overridden with the `vault.approle`
// copy (same precedent as AgentsSection's `agentUrl` override), since the
// server schema's own description only covers `token` vs `approle` in the
// abstract, not what AppRole itself needs.
function vaultUiSchema(value: Record<string, unknown>): UiSchema {
  const approle = value.authMethod === 'approle';
  return {
    authMethod: { 'ui:description': help['vault.approle'].text },
    token: approle ? { 'ui:widget': 'hidden' } : {},
    roleId: approle ? {} : { 'ui:widget': 'hidden' },
    secretId: approle ? {} : { 'ui:widget': 'hidden' },
  };
}

// Batch 3 review (Critical, IntegrationsSection.tsx:28): the server's own
// `checkSettings` (internal/vault/settings.go) 422s "token requires
// authMethod token" if `token` is present at all under `authMethod:
// 'approle'` (even as the `__unchanged__` sentinel) — and the same for
// `roleId`/`secretId` under `authMethod: 'token'` — so a section with a
// stored token could never switch to AppRole, and vice versa. Both the Save
// and Test bodies drop whichever pair doesn't apply to the live
// authMethod; the hidden field's own value stays in `value`/the draft, so
// switching back doesn't lose what was typed.
function pruneAuthMethod(value: Record<string, unknown>): Record<string, unknown> {
  const out = { ...value };
  if (out.authMethod === 'approle') delete out.token;
  else {
    delete out.roleId;
    delete out.secretId;
  }
  return out;
}

// Batch 3 review (Critical, SchemaSection.tsx:150): the generic
// `fieldErrorFromMessage` maps the 422 "re-enter the token" (5a-facts.md:
// sent for both authMethod token and approle, same wording either way) to
// its literal `token` match — wrong, and invisible, when `authMethod` is
// `approle`, since `token` is hidden. Route it to whichever secret field is
// actually live instead; anything else falls back to the generic mapper.
function mapVaultSaveError(message: string, value: Record<string, unknown>, schema: RJSFSchema): ErrorSchema | null {
  if (/\bre-enter the token\b/i.test(message)) {
    const field = value.authMethod === 'approle' ? 'secretId' : 'token';
    return { [field]: { __errors: [message] } } as ErrorSchema;
  }
  return fieldErrorFromMessage(schema, message);
}

function humanizeTtl(seconds: number): string {
  if (seconds >= 86_400) return `${Math.round(seconds / 86_400)} d`;
  if (seconds >= 3_600) return `${Math.round(seconds / 3_600)} h`;
  if (seconds >= 60) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds)} s`;
}

const POLICY_LIMIT = 5;

function TestResult({ result }: { result: VaultTestResult }) {
  if (result.ok) {
    const shown = (result.policies ?? []).slice(0, POLICY_LIMIT);
    const rest = (result.policies?.length ?? 0) - shown.length;
    return (
      <div className="flex flex-wrap items-center gap-2">
        <ToneChip tone="valid" icon={CircleCheck} label="Connected" />
        {(result.tokenTtlSeconds != null || result.version) && (
          <span className="font-mono text-xs text-ink-muted">
            {result.tokenTtlSeconds != null && `TTL ${humanizeTtl(result.tokenTtlSeconds)}`}
            {result.tokenTtlSeconds != null && result.version && ' · '}
            {result.version && `v${result.version}`}
          </span>
        )}
        {shown.map((p) => (
          <Badge key={p} variant="secondary">
            {p}
          </Badge>
        ))}
        {rest > 0 && <Badge variant="secondary">+{rest}</Badge>}
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ToneChip tone="failed" icon={CircleX} label="Failed" />
      {result.error && <span className="text-sm text-ink-muted">{result.error}</span>}
    </div>
  );
}

// Direct call (not useMutation), same reasoning as `saveSettingsDirect`
// (SchemaSection, "Secrets" global constraint): the token/secretId never
// sit in the mutation cache, whether the test succeeds or fails.
function VaultTest({ value }: { value: Record<string, unknown> }) {
  const me = useMe();
  const canWrite = can(me, 'settings:write');
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<VaultTestResult | null>(null);

  // "The result is held in local state and cleared whenever the draft
  // changes" (brief). Batch 3 review (Minor, :91): `value` is a *new*
  // `withSecretSentinels` object on every SchemaSection render even with no
  // actual edit (e.g. a background refetch on window focus), so a
  // reference-keyed effect cleared the result on more than edits alone —
  // keyed on a content signature instead, so only an actual field change
  // clears it.
  const signature = JSON.stringify(value);
  useEffect(() => setResult(null), [signature]);

  async function runTest() {
    setTesting(true);
    try {
      setResult(await testVault(pruneAuthMethod(value) as VaultSettings));
    } catch (e) {
      setResult({ ok: false, error: errorMessage(e) });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <PermissionTip allowed={canWrite} action="settings:write">
        <Button type="button" variant="outline" disabled={!canWrite || testing || !value.address} onClick={() => void runTest()}>
          {testing ? 'Testing…' : 'Test connection'}
        </Button>
      </PermissionTip>
      <HelpTip id="vault.test" />
      {result && <TestResult result={result} />}
    </div>
  );
}

// Task 6: the smtp section's own 422s (internal/notify/settings.go's
// checkSMTPReentry and checkSMTPSettings) name `password` and `username`
// literally, and both are always visible fields (unlike Vault's
// authMethod-hidden token/secretId), so this needs no sibling-value lookup
// — just routes each known message to its field before falling back to the
// generic mapper.
function mapSmtpSaveError(message: string, _value: Record<string, unknown>, schema: RJSFSchema): ErrorSchema | null {
  // A computed property key, same as mapVaultSaveError above: TS treats a
  // literal `{ password: ... }` cast to `ErrorSchema` as an "insufficient
  // overlap" mistake, but a `{ [field]: ... }` one as matching its index
  // signature.
  let field: string | null = null;
  if (/\bre-enter the password\b/i.test(message)) field = 'password';
  else if (/\bauthentication requires tls\b/i.test(message)) field = 'username';
  if (field) return { [field]: { __errors: [message] } } as ErrorSchema;
  return fieldErrorFromMessage(schema, message);
}

export function IntegrationsSection() {
  const keysStatus = useQuery(keysStatusQuery);
  return (
    <div className="grid max-w-[720px] gap-8">
      {keysStatus.data?.kind === 'vault-transit' && (
        <div className="flex items-center gap-1.5 text-sm">
          <span className="font-medium">Transit KEK</span>
          <span className="font-mono text-xs text-ink-muted">{keysStatus.data.vaultAddress}</span>
          <HelpTip id="vault.transitKek" />
        </div>
      )}
      <SchemaSection
        section="vault"
        title="Vault"
        help="settings.vault"
        saveMode="direct"
        uiSchemaOverrides={vaultUiSchema}
        prepareBody={pruneAuthMethod}
        mapSaveError={mapVaultSaveError}
        actions={(value) => <VaultTest value={value} />}
      />
      <SchemaSection
        section="smtp"
        title="Email (SMTP)"
        help="settings.smtp"
        saveMode="direct"
        mapSaveError={mapSmtpSaveError}
        actions={(value, { dirty }) => <SmtpTest value={value} dirty={dirty} />}
      />
      <SchemaSection section="notifications" title="Notifications" help="settings.notifications" />
      <SchemaSection
        section="prometheus"
        title="Prometheus"
        help="settings.prometheus"
        saveMode="direct"
        actions={() => <PrometheusScrape />}
      />
    </div>
  );
}
