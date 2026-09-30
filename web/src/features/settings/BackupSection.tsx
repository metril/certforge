import { useState } from 'react';
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { toast } from 'sonner';
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { backupStatusQuery, downloadBackup } from '@/api/queries/backup';
import { errorMessage } from '@/api/errors';
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

/** Downloads a fresh backup archive (task-7-brief), shared by the section's
 * own "Back up now" button and CommandPalette's "Settings: Back up now"
 * entry. Toasts either way and refreshes `['backup-status']` (a completed
 * on-demand backup moves `lastSuccessAt`/`lastSizeBytes`/`lastFile`; a 409
 * changes nothing server-side, but the brief still calls for a refetch).
 * Rethrows so a caller that needs to react further — the palette navigates
 * to Settings → Backup and keys on a 409 — can do so without re-toasting. */
export async function runBackup(qc: QueryClient): Promise<void> {
  try {
    await downloadBackup();
    toast.success('Backup downloaded');
  } catch (e) {
    toast.error(errorMessage(e));
    throw e;
  } finally {
    await qc.invalidateQueries({ queryKey: ['backup-status'] });
  }
}

/** "Back up now" is disabled two independent ways (same precedent as
 * EncryptionKeyCard's RewrapButton): no `settings:write` (PermissionTip's
 * own tooltip), or escrow not yet confirmed (`backup.needsEscrow`, which
 * carries its own "Learn more" link — a plain PermissionTip `reason` string
 * can't). Both never need to combine in one render, so whichever applies
 * wins outright. */
function BackUpNowButton({
  canWrite,
  escrowConfirmed,
  running,
  onClick,
}: {
  canWrite: boolean;
  escrowConfirmed: boolean;
  running: boolean;
  onClick: () => void;
}) {
  const btn = (
    <Button type="button" disabled={!canWrite || !escrowConfirmed || running} onClick={onClick}>
      <Download className="size-3.5" aria-hidden />
      {running ? 'Backing up…' : 'Back up now'}
    </Button>
  );
  if (!canWrite) return <PermissionTip allowed={false} action="settings:write">{btn}</PermissionTip>;
  if (!escrowConfirmed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="inline-flex">
            {btn}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
          <HelpTipBody entry={help['backup.needsEscrow']} />
        </TooltipContent>
      </Tooltip>
    );
  }
  return btn;
}

// `retainCount`/`directory` only matter once something is actually
// scheduled; `directory` gets the mono font (task-7-brief) the rest of the
// time (Task 8's `target.vaultKv` precedent for `ui:options.mono` on a
// plain string field).
function backupUiSchema(value: Record<string, unknown>): UiSchema {
  if (value.schedule === 'off') {
    return { retainCount: { 'ui:widget': 'hidden' }, directory: { 'ui:widget': 'hidden' } };
  }
  return { directory: { 'ui:options': { mono: true } } };
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

/** Settings → Backup and keys' own backup section (task-7-brief), mounted
 * after `EncryptionKeyCard` by SettingsPage. */
export function BackupSection() {
  const me = useMe();
  const qc = useQueryClient();
  const canWrite = can(me, 'settings:write');
  const status = useQuery(backupStatusQuery);
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
            escrowConfirmed={status.data?.escrowConfirmed ?? false}
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
