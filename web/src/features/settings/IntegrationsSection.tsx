import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleCheck, CircleX } from 'lucide-react';
import type { UiSchema } from '@rjsf/utils';
import { keysStatusQuery } from '@/api/queries/keys';
import { testVault } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import type { VaultSettings, VaultTestResult } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { SchemaSection } from './SchemaSection';

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
  // changes" (brief) — `value` is a fresh object on every field edit
  // (SchemaSection's draft state), so a reference-keyed effect is exactly
  // that signal.
  useEffect(() => setResult(null), [value]);

  async function runTest() {
    setTesting(true);
    try {
      setResult(await testVault(value as VaultSettings));
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
        actions={(value) => <VaultTest value={value} />}
      />
    </div>
  );
}
