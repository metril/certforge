import { useDirty } from '@/lib/useDirty';
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { allCertificatesQuery } from '@/api/queries/certificates';
import { useCheckMonitor, useCreateMonitor, useDeleteMonitor, useUpdateMonitor } from '@/api/queries/monitors';
import type { Monitor, MonitorInput } from '@/api/types';
import { Combobox, type ComboOption } from '@/components/Combobox';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { CopyField } from '@/components/CopyField';
import { FormSection } from '@/components/FormSection';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose, useSheetGuard } from '@/components/ui/sheet';
import { fieldErrorFromMessage } from '@/forms/uiSchema';
import { INTERVALS, fmtInterval } from '@/lib/monitors';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { ExpiryChip } from './ExpiryChip';
import { MonitorStateChip } from './MonitorStateChip';
import { ReadOnlyNotice } from './ReadOnlyNotice';

// A minimal schema, shaped only enough for fieldErrorFromMessage's own
// per-field name matching (Field.error below, not a SchemaForm) — this
// sheet has plain fields, not a notifier config form.
const MONITOR_SCHEMA: RJSFSchema = {
  type: 'object',
  properties: { name: {}, host: {}, port: {}, sni: {}, intervalSeconds: {}, expectedCertificateId: {} },
};

const ANY_CERT = '__any__';
const INTERVAL_OPTIONS = INTERVALS.map((i) => ({ value: String(i.value), label: i.label }));

function fieldErrors(es: ErrorSchema | null): Record<string, string> {
  if (!es) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(es)) {
    const errs = (v as { __errors?: string[] } | undefined)?.__errors;
    if (errs?.[0]) out[k] = errs[0];
  }
  return out;
}

type Draft = { name: string; host: string; port: string; sni: string; intervalSeconds: number; expectedCertificateId: string | null; enabled: boolean };

function initialDraft(monitor?: Monitor): Draft {
  return {
    name: monitor?.name ?? '',
    host: monitor?.host ?? '',
    port: String(monitor?.port ?? 443),
    sni: monitor?.sni ?? '',
    intervalSeconds: monitor?.intervalSeconds ?? 3600,
    expectedCertificateId: monitor?.expectedCertificateId ?? null,
    enabled: monitor?.enabled ?? true,
  };
}

function toInput(d: Draft): MonitorInput {
  return {
    name: d.name,
    host: d.host,
    port: Number(d.port),
    sni: d.sni.trim() === '' ? null : d.sni,
    intervalSeconds: d.intervalSeconds,
    expectedCertificateId: d.expectedCertificateId,
    enabled: d.enabled,
  };
}

/** Whether saving `d` over `monitor` resets its state to Unknown (Shared
 * contracts, Monitor operations: changing host, port, sni or the expected
 * certificate does). */
function targetChanged(monitor: Monitor, d: Draft): boolean {
  return monitor.host !== d.host || monitor.port !== Number(d.port) || (monitor.sni ?? '') !== d.sni || monitor.expectedCertificateId !== d.expectedCertificateId;
}

type Props = { orgId: string; open: boolean; monitor?: Monitor; onOpenChange: (open: boolean) => void };

export function MonitorSheet({ orgId, open, monitor, onOpenChange }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const qc = useQueryClient();
  const me = useMe();
  const { data: allCerts = [] } = useQuery(allCertificatesQuery(orgId));
  const [draft, setDraft] = useState<Draft>(() => initialDraft(monitor));
  const [submitted, setSubmitted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const dirty = useDirty(draft);
  const create = useCreateMonitor(orgId);
  const update = useUpdateMonitor(orgId, monitor?.id ?? '');
  const check = useCheckMonitor(orgId);
  const del = useDeleteMonitor(orgId);

  const canWrite = can(me, 'alerts:write', orgId);
  const nameOk = draft.name.trim() !== '';
  const hostOk = draft.host.trim() !== '';
  const portOk = /^\d+$/.test(draft.port.trim()) && Number(draft.port) >= 1 && Number(draft.port) <= 65535;
  const presetSelected = INTERVALS.some((i) => i.value === draft.intervalSeconds);

  const certOptions: ComboOption[] = [
    { value: ANY_CERT, label: 'Any CertForge certificate' },
    ...allCerts.map((c) => ({ value: c.id, label: c.name })),
  ];

  async function submit() {
    setSubmitted(true);
    setServerErrors({});
    if (!nameOk || !hostOk || !portOk) return;
    setSaving(true);
    try {
      const input = toInput(draft);
      if (monitor) {
        await update.mutateAsync(input);
        toast.success(targetChanged(monitor, draft) ? 'Monitor saved; state resets to Unknown' : 'Monitor saved');
      } else {
        await create.mutateAsync(input);
      }
      await qc.invalidateQueries({ queryKey: ['monitors', orgId] });
      guard.close();
    } catch (e) {
      const message = errorMessage(e);
      if (e instanceof ApiError && e.status === 422) {
        const mapped = fieldErrors(fieldErrorFromMessage(MONITOR_SCHEMA, message));
        if (Object.keys(mapped).length > 0) setServerErrors(mapped);
        else toast.error(message);
      } else {
        toast.error(message);
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet guard={guard} open={open} form dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader className="flex-row items-start justify-between gap-2">
          <div>
            <SheetTitle>{monitor ? monitor.name : 'New monitor'}</SheetTitle>
            <SheetDescription className="sr-only">External TLS monitor settings</SheetDescription>
          </div>
          {monitor && (
            <span className="inline-flex items-center gap-1">
              <PermissionTip allowed={canWrite} action="alerts:write">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!canWrite || check.isPending}
                  onClick={() => check.mutate(monitor.id, { onError: (e) => toast.error(errorMessage(e)) })}
                >
                  <RefreshCw className={check.isPending ? 'size-3.5 animate-spin' : 'size-3.5'} aria-hidden />
                  Check now
                </Button>
              </PermissionTip>
              <HelpTip id="monitor.check" />
            </span>
          )}
        </SheetHeader>
        <div className="grid gap-5 px-4">
          {!canWrite && <ReadOnlyNotice reason="Needs the alerts:write permission" />}
          {monitor?.lastCheckedAt && (
            <div className="grid gap-2 rounded-md border border-border p-3">
              <span className="text-sm font-semibold">Last check</span>
              <div className="grid gap-1.5 text-sm">
                <span className="flex items-center gap-1.5">
                  <MonitorStateChip state={monitor.state} enabled={monitor.enabled} lastError={monitor.lastError} />
                  <span className="text-xs text-ink-muted">{relTime(monitor.lastCheckedAt)}</span>
                </span>
                {monitor.lastFingerprint && (
                  <span className="flex items-center gap-1.5">
                    <span className="text-xs text-ink-muted">Fingerprint</span>
                    <CopyField value={monitor.lastFingerprint} label="fingerprint" />
                  </span>
                )}
                {monitor.lastIssuer && (
                  <span className="flex items-start gap-1.5">
                    <span className="shrink-0 text-xs text-ink-muted">Issuer</span>
                    <span className="break-words font-mono text-xs">{monitor.lastIssuer}</span>
                  </span>
                )}
                {monitor.lastNotAfter && (
                  <span className="flex items-center gap-1.5">
                    <span className="text-xs text-ink-muted">Expires</span>
                    <ExpiryChip notAfter={monitor.lastNotAfter} />
                  </span>
                )}
                <span className="flex items-center gap-1.5">
                  <span className="text-xs text-ink-muted">Expected</span>
                  <span>{monitor.expectedCertificateName ?? 'Any CertForge certificate'}</span>
                </span>
                {monitor.lastError && <span className="text-xs text-ink-muted">{monitor.lastError}</span>}
              </div>
            </div>
          )}
          <form
            className="grid gap-5"
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <Field id="monitor-name" label="Name" error={(submitted && !nameOk ? 'Required' : null) ?? serverErrors.name}>
              <Input
                id="monitor-name"
                value={draft.name}
                onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                placeholder="edge"
                disabled={!canWrite}
              />
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-[2fr_1fr]">
              <Field id="monitor-host" label="Host" error={(submitted && !hostOk ? 'Required' : null) ?? serverErrors.host}>
                <Input
                  id="monitor-host"
                  className="font-mono text-xs"
                  value={draft.host}
                  onChange={(e) => setDraft((d) => ({ ...d, host: e.target.value }))}
                  placeholder="edge.example.com"
                  disabled={!canWrite}
                />
              </Field>
              <Field id="monitor-port" label="Port" error={(submitted && !portOk ? 'Port must be 1-65535' : null) ?? serverErrors.port}>
                <Input
                  id="monitor-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={draft.port}
                  onChange={(e) => setDraft((d) => ({ ...d, port: e.target.value }))}
                  disabled={!canWrite}
                />
              </Field>
            </div>
            <Field id="monitor-interval" label="Check interval" help="monitor.interval" error={serverErrors.intervalSeconds}>
              <div className="grid gap-1">
                <SegmentedControl
                  id="monitor-interval"
                  aria-label="Check interval"
                  value={presetSelected ? String(draft.intervalSeconds) : ''}
                  onChange={(v) => setDraft((d) => ({ ...d, intervalSeconds: Number(v) }))}
                  options={INTERVAL_OPTIONS.map((o) => ({ ...o, disabled: !canWrite, hint: !canWrite ? 'Needs the alerts:write permission' : undefined }))}
                />
                {!presetSelected && <span className="text-xs text-ink-muted">Currently {fmtInterval(draft.intervalSeconds)}</span>}
              </div>
            </Field>
            <SwitchField
              id="monitor-enabled"
              label="Enabled"
              checked={draft.enabled}
              disabled={!canWrite}
              onCheckedChange={(enabled) => setDraft((d) => ({ ...d, enabled }))}
            />
            <FormSection
              title="Advanced"
              collapsible
              count={(draft.sni.trim() !== '' ? 1 : 0) + (draft.expectedCertificateId ? 1 : 0)}
              forceOpen={!!(serverErrors.sni || serverErrors.expectedCertificateId)}
            >
            <Field id="monitor-sni" label="SNI" help="monitor.sni" optional error={serverErrors.sni}>
              <Input
                id="monitor-sni"
                className="font-mono text-xs"
                value={draft.sni}
                placeholder={draft.host || 'host'}
                onChange={(e) => setDraft((d) => ({ ...d, sni: e.target.value }))}
                disabled={!canWrite}
              />
            </Field>
            <Field id="monitor-expected" label="Expected certificate" help="monitor.expected" error={serverErrors.expectedCertificateId}>
              <Combobox
                id="monitor-expected"
                aria-label="Expected certificate"
                value={draft.expectedCertificateId ?? ANY_CERT}
                onChange={(v) => setDraft((d) => ({ ...d, expectedCertificateId: !v || v === ANY_CERT ? null : v }))}
                options={certOptions}
                placeholder="Any CertForge certificate"
                emptyText="No certificate matches."
                disabled={!canWrite}
              />
            </Field>
            </FormSection>
            <SheetFooter className="flex-row justify-between gap-2 px-0">
              {monitor ? (
                <PermissionTip allowed={canWrite} action="alerts:write">
                  <Button type="button" variant="destructive" disabled={!canWrite} onClick={() => setConfirmingDelete(true)}>
                    Delete
                  </Button>
                </PermissionTip>
              ) : (
                <span />
              )}
              <span className="flex gap-2">
                <SheetClose asChild>
                  <Button type="button" variant="outline">Cancel</Button>
                </SheetClose>
                <PermissionTip allowed={canWrite} action="alerts:write">
                  <Button type="submit" disabled={!canWrite || saving}>
                    Save
                  </Button>
                </PermissionTip>
              </span>
            </SheetFooter>
          </form>
        </div>
      </SheetContent>
      {monitor && (
        <ConfirmDestructive
          open={confirmingDelete}
          onOpenChange={setConfirmingDelete}
          title="Delete monitor?"
          consequence="Checks stop; past events stay in the event log."
          confirmText={monitor.name}
          actionLabel="Delete monitor"
          onConfirm={async () => {
            // useDeleteMonitor's own onSuccess already invalidates ['monitors', orgId].
            await del.mutateAsync(monitor.id);
            guard.close();
          }}
        />
      )}
    </Sheet>
  );
}
