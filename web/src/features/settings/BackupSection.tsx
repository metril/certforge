import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { runBackup } from '@/api/queries/backup';
import { HelpTip, HelpTipBody } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { fieldErrorFromMessage } from '@/forms/uiSchema';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { BackupStatusCard } from './BackupStatusCard';
import { SchemaSection } from './SchemaSection';

/** "Back up now": disabled without `settings:write` (PermissionTip's own
 * tooltip) or while a backup runs; otherwise its tooltip is the key reminder. */
function BackUpNowButton({ canWrite, running, onClick }: { canWrite: boolean; running: boolean; onClick: () => void }) {
  const btn = (
    <Button type="button" disabled={!canWrite || running} onClick={onClick}>
      <Download className="size-3.5" aria-hidden />
      {running ? 'Backing up…' : 'Back up now'}
    </Button>
  );
  if (!canWrite) return <PermissionTip allowed={false} action="settings:write">{btn}</PermissionTip>;
  if (running) return btn;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{btn}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
        <HelpTipBody entry={help['backup.keyReminder']} />
      </TooltipContent>
    </Tooltip>
  );
}

// Batch 3 review fix: the plain `off`/`daily`/`weekly` enum has no title per
// value for the SegmentedControl's own `enumOptions[].label` (RJSF's
// `optionsList`, forms/theme/widgets.tsx:58) to pick up — `ui:enumNames`
// (any `ui:xxx` key is folded into `ui:options` by RJSF's own `getUiOptions`)
// supplies "Off"/"Daily"/"Weekly" without touching the schema itself. Needed
// in both branches: it's the segmented control's own labels, not tied to
// whether retainCount/directory are shown.
//
// `retainCount`/`directory` only matter once something is actually
// scheduled; `directory` gets the mono font (task-7-brief) the rest of the
// time (Task 8's `target.vaultKv` precedent for `ui:options.mono` on a
// plain string field).
function backupUiSchema(value: Record<string, unknown>): UiSchema {
  const schedule = { 'ui:enumNames': ['Off', 'Daily', 'Weekly'] };
  if (value.schedule === 'off') {
    return { schedule, retainCount: { 'ui:widget': 'hidden' }, directory: { 'ui:widget': 'hidden' } };
  }
  return { schedule, directory: { 'ui:options': { mono: true } } };
}

// The backup section's own 422s (internal/backup's checkSettings) name
// `directory` in prose ("... is not a writable directory", "directory is
// required when schedule is not off") rather than the literal key alone, so
// the generic `fieldErrorFromMessage` (a `\bdirectory\b` match) would
// already catch these — this exists to document the two exact phrases the
// brief calls out, same precedent as mapSmtpSaveError/mapVaultSaveError.
// A computed, `string`-widened property key (not a literal `{ directory:
// ... }`, and not a `const` binding, which TS would narrow right back to
// the literal type), same as those two: TS treats a literal key cast to
// `ErrorSchema` as an "insufficient overlap" mistake, but a `string`-typed
// one as matching its index signature.
function mapBackupSaveError(message: string, _value: Record<string, unknown>, schema: RJSFSchema): ErrorSchema | null {
  let field: string | null = null;
  if (/\bwritable directory\b/i.test(message) || /\brequired when schedule\b/i.test(message)) field = 'directory';
  if (field) return { [field]: { __errors: [message] } } as ErrorSchema;
  return fieldErrorFromMessage(schema, message);
}

/** Settings → Backups' own backup section (task-7-brief), mounted
 * before `EncryptionKeyCard` by SettingsPage. */
export function BackupSection() {
  const me = useMe();
  const qc = useQueryClient();
  const canWrite = can(me, 'settings:write');
  const [running, setRunning] = useState(false);

  async function handleBackup() {
    setRunning(true);
    try {
      await runBackup(qc);
    } catch {
      // Already toasted by runBackup.
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="grid max-w-[720px] gap-6">
      <BackupStatusCard />
      <div className="flex flex-wrap items-center gap-6">
        <div className="flex items-center gap-2">
          <BackUpNowButton
            canWrite={canWrite}
            running={running}
            onClick={() => void handleBackup()}
          />
          <HelpTip id="backup.now" />
        </div>
        <div className="flex items-center gap-1.5 text-sm text-ink-muted">
          Restore
          <HelpTip id="backup.restore" />
        </div>
      </div>
      <SchemaSection
        section="backup"
        uiSchemaOverrides={backupUiSchema}
        mapSaveError={mapBackupSaveError}
        onSaved={() => void qc.invalidateQueries({ queryKey: ['backup-status'] })}
      />
    </div>
  );
}
