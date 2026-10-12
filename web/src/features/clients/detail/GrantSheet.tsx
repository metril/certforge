import { useDirty } from '@/lib/useDirty';
import { useMemo, useRef, useState, type ReactNode } from 'react';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, CircleAlert, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { allCertificatesPickerQuery, plural } from '@/api/queries/certificates';
import { deployTargetsQuery, hooksQuery, layoutsQuery } from '@/api/queries/delivery';
import { metaSchemasQuery } from '@/api/queries/dns';
import { useCreateGrants, useUpdateGrant, type GrantBatchResult } from '@/api/queries/grants';
import type { Client, Grant, GrantDelivery } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { FormSection } from '@/components/FormSection';
import { Field } from '@/components/Field';
import { MultiCombobox } from '@/components/MultiCombobox';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ToneChip } from '@/components/StatusChip';
import { SwitchField } from '@/components/SwitchField';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose, useSheetGuard } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage } from '@/forms/uiSchema';
import { HelpTip } from '@/components/HelpTip';
import { PHASE_LABEL } from '@/lib/clientStatus';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { IconButton } from '@/components/IconButton';

type Props = { orgId: string; client: Client; grants: Grant[]; editing?: Grant; /** The grant vanished from the poll while the sheet was open: show the snapshot's name and a removed notice, no form. */ removed?: boolean; onOpenChange: (open: boolean) => void };

/** A field whose options come from a query: a skeleton while pending, an
 * inline error (with retry) on failure, never the "nothing yet" empty text
 * for either — that text is reserved for a settled, genuinely empty list. */
function QueryField({ label, q, children }: { label: string; q: UseQueryResult<unknown>; children: ReactNode }) {
  if (q.isPending) return <div aria-busy="true" aria-label={`Loading ${label}`} className="h-9 animate-pulse rounded-md bg-subtle" />;
  if (q.isError)
    return (
      <p role="alert" className="flex flex-wrap items-center gap-2 text-sm text-failed">
        <CircleAlert className="size-3.5 shrink-0" aria-hidden />
        <span className="flex-1">{`Couldn't load ${label}. ${errorMessage(q.error)}`}</span>
        <Button variant="outline" size="sm" onClick={() => void q.refetch()}>
          Retry
        </Button>
      </p>
    );
  return <>{children}</>;
}

const fieldErr = (key: string, msg: string) => ({ [key]: { __errors: [msg] } }) as unknown as ErrorSchema;

const fileHasKey = (f: { format: string; parts?: string[] }) =>
  f.format === 'p12' || f.format === 'jks' || !!f.parts?.some((p) => p === 'key' || p === 'combined');

export function GrantSheet({ orgId, client, grants, editing, removed = false, onOpenChange }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const certs = useQuery(allCertificatesPickerQuery(orgId));
  const layoutsQ = useQuery(layoutsQuery(orgId));
  const targetsQ = useQuery(deployTargetsQuery(orgId));
  const hooksQ = useQuery(hooksQuery(orgId));
  const layouts = layoutsQ.data ?? [];
  const targets = targetsQ.data ?? [];
  const hooks = hooksQ.data ?? [];
  const { data: meta } = useQuery(metaSchemasQuery);
  const create = useCreateGrants(orgId, client.id);
  const update = useUpdateGrant(orgId);
  const [certIds, setCertIds] = useState<string[]>([]);
  const [delivery, setDelivery] = useState<GrantDelivery>(editing?.delivery ?? 'push');
  const [layoutId, setLayoutId] = useState<string | undefined>(editing?.layoutId ?? undefined);
  const [targetId, setTargetId] = useState<string | undefined>(editing?.deployTargetId ?? undefined);
  const [hookIds, setHookIds] = useState<string[]>(editing?.hookIds ?? []);
  const [autoRemediate, setAutoRemediate] = useState(editing?.autoRemediate ?? false);
  const [errors, setErrors] = useState<{ certs?: string; where?: string }>({});
  const [failures, setFailures] = useState<GrantBatchResult['failed']>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [targetOptions, setTargetOptions] = useState<Record<string, unknown>>(editing?.targetOptions ?? {});
  const [optsExtra, setOptsExtra] = useState<ErrorSchema | null>(null);
  const optsRef = useRef<SchemaFormHandle>(null);
  const selectedTarget = targets.find((t) => t.id === targetId);
  const grantSchema = useMemo(
    () => meta?.deployTargets.find((t) => t.code === selectedTarget?.type)?.grantSchema as RJSFSchema | undefined,
    [meta, selectedTarget?.type],
  );
  const showOpts = !!targetId && !!grantSchema;
  // Unset-equivalent values (false, '', []) are dropped: the form fills defaults such as
  // defaultCert: false on mount, possibly after the first-render snapshot (meta loads async).
  const dirty = useDirty({ certIds, delivery, layoutId, targetId, hookIds, autoRemediate, targetOptions: Object.fromEntries(Object.entries(targetOptions).filter(([, v]) => v !== false && v !== '' && v !== undefined && !(Array.isArray(v) && v.length === 0))) });
  // A 422 titles the field "Invalid targetOptions.<key>"; failing that, match a
  // schema key named in the message. A 409 about the default certificate belongs
  // under its switch.
  const optsFieldError = (msg: string, status?: number, title?: string): ErrorSchema | null => {
    if (!showOpts) return null;
    const key = fieldOfTitle(title) === 'targetOptions' ? title?.split('.')[1] : undefined;
    if (key && grantSchema.properties?.[key]) return fieldErr(key, msg);
    const field = fieldErrorFromMessage(grantSchema, msg.replace(/\btargetOptions\./g, ''));
    if (field) return field;
    if (status === 409 && /default/i.test(msg)) return fieldErr('defaultCert', msg);
    return null;
  };
  const busy = create.isPending || update.isPending;
  // Mirrors the server's agent-grant rule: any deploy target, or a layout with
  // a key-bearing file, hands the agent a private key and needs keys:export.
  const layoutKeyed = layouts.find((l) => l.id === layoutId)?.files.some(fileHasKey) ?? false;
  const keyed = !!targetId || layoutKeyed;
  const canExportKeys = can(useMe(), 'keys:export', orgId);
  const keyBlocked = keyed && !canExportKeys;

  const granted = new Set(grants.map((g) => g.certificateId));
  const certOptions = (certs.data ?? [])
    .filter((c) => !granted.has(c.id))
    .map((c) => ({ value: c.id, label: c.name, hint: c.commonName, keywords: [c.commonName, ...c.sans] }));
  const certName = (id: string) => certs.data?.find((c) => c.id === id)?.name ?? id;
  const typeName = (code: string) => meta?.deployTargets.find((t) => t.code === code)?.name ?? code;
  // hookIds is the run order sent to the server; ChipSet appends picks, the
  // ordered list below shows and changes that order.
  const moveHook = (i: number, d: -1 | 1) => {
    const next = [...hookIds];
    [next[i], next[i + d]] = [next[i + d]!, next[i]!];
    setHookIds(next);
  };

  const submit = async () => {
    const next: typeof errors = {};
    if (!editing && certIds.length === 0) next.certs = 'Pick at least one certificate.';
    if (!layoutId && !targetId) next.where = 'Pick a layout, a deploy target, or both.';
    setErrors(next);
    setFormError(null);
    setFailures([]);
    setOptsExtra(null);
    if (next.certs || next.where) return;
    if (showOpts && !optsRef.current?.validate()) return;
    const rest = { delivery, layoutId: layoutId ?? null, deployTargetId: targetId ?? null, hookIds, autoRemediate, targetOptions: showOpts ? targetOptions : {} };
    if (editing) {
      try {
        await update.mutateAsync({ id: editing.id, body: rest });
        guard.close();
      } catch (e) {
        const msg = errorMessage(e);
        const field = optsFieldError(msg, e instanceof ApiError ? e.status : undefined, e instanceof ApiError ? e.problem.title : undefined);
        if (field) setOptsExtra(field);
        else setFormError(msg);
      }
      return;
    }
    const r = await create.mutateAsync({ certificateIds: certIds, rest });
    if (r.created.length > 0) toast.success(`Granted ${plural(r.created.length, 'certificate')}`);
    if (r.failed.length === 0) {
      guard.close();
      return;
    }
    setCertIds(r.failed.map((f) => f.certificateId));
    setFailures(r.failed);
    // Every certificate failed on the same options field: mark that field too.
    const marks = r.failed.map((f) => optsFieldError(f.message, f.status, f.title));
    if (marks.every((m) => m) && new Set(marks.map((m) => Object.keys(m!)[0])).size === 1) setOptsExtra(marks[0]!);
  };

  return (
    <Sheet guard={guard} open form dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{editing ? `Edit ${editing.certificateName}` : 'Grant certificate'}</SheetTitle>
          <SheetDescription className="sr-only">For client {client.name}</SheetDescription>
        </SheetHeader>
        {removed ? (
          <p role="alert" className="flex items-center gap-1.5 px-4 text-sm">
            <CircleAlert className="size-4 shrink-0 text-failed" aria-hidden />
            This grant was removed. Close this sheet to continue.
          </p>
        ) : (
        <div className="grid gap-5 px-4">
          {editing ? (
            <div className="grid gap-1 text-sm">
              <span className="text-ink-muted">Certificate</span>
              <span className="font-semibold">{editing.certificateName}</span>
            </div>
          ) : (
            <Field id="grant-certs" label="Certificates" help="grant.certificates" error={errors.certs}>
              <QueryField label="certificates" q={certs}>
                <MultiCombobox
                  id="grant-certs"
                  aria-label="Certificates"
                  value={certIds}
                  onChange={(v) => {
                    setCertIds(v);
                    setErrors((e) => ({ ...e, certs: undefined }));
                  }}
                  options={certOptions}
                  placeholder="Pick certificates"
                  emptyText="No certificate to grant."
                />
              </QueryField>
            </Field>
          )}
          <Field id="grant-delivery" label="Delivery" help="grant.delivery">
            <div className="flex flex-wrap items-center gap-2">
              <SegmentedControl<GrantDelivery>
                id="grant-delivery"
                aria-label="Delivery"
                value={delivery}
                onChange={setDelivery}
                options={[
                  { value: 'push', label: 'Push' },
                  { value: 'pull', label: 'Pull' },
                ]}
              />
              {delivery === 'pull' && <ToneChip tone="expiring" icon={TriangleAlert} label="No push" help="grant.pullWarning" />}
            </div>
          </Field>
          <Field id="grant-layout" label="Layout" help="grant.layout" optional>
            <QueryField label="layouts" q={layoutsQ}>
              <Combobox
                id="grant-layout"
                aria-label="Layout"
                clearable
                value={layoutId}
                onChange={(v) => {
                  setLayoutId(v);
                  setErrors((e) => ({ ...e, where: undefined }));
                }}
                options={layouts.map((l) => ({ value: l.id, label: l.name, hint: plural(l.files.length, 'file') }))}
                placeholder="No layout"
                emptyText="No layouts yet."
              />
            </QueryField>
          </Field>
          <Field id="grant-target" label="Deploy target" help="grant.target" optional error={errors.where}>
            <QueryField label="deploy targets" q={targetsQ}>
              <Combobox
                id="grant-target"
                aria-label="Deploy target"
                clearable
                value={targetId}
                onChange={(v) => {
                  const nextType = targets.find((t) => t.id === v)?.type;
                  if (nextType !== selectedTarget?.type) {
                    setTargetOptions({});
                    setOptsExtra(null);
                  }
                  setTargetId(v);
                  setErrors((e) => ({ ...e, where: undefined }));
                }}
                options={targets.map((t) =>
                  t.runsOn === 'server'
                    ? { value: t.id, label: t.name, disabled: true, hint: help['grant.serverTarget'].text }
                    : { value: t.id, label: t.name, hint: typeName(t.type) },
                )}
                placeholder="No target"
                emptyText="No deploy targets yet."
              />
            </QueryField>
          </Field>
          {showOpts && (
            <div className="grid gap-1.5">
              <span className="inline-flex items-center gap-1.5 text-sm font-semibold">
                Target options
                <HelpTip id="grant.targetOptions" />
              </span>
              <SchemaForm
                ref={optsRef}
                schema={grantSchema}
                value={targetOptions}
                onChange={(v) => {
                  setTargetOptions(v);
                  setOptsExtra(null);
                }}
                extraErrors={optsExtra ?? undefined}
              />
            </div>
          )}
          <FormSection title="Advanced" collapsible count={(hookIds.length > 0 ? 1 : 0) + (autoRemediate ? 1 : 0)}>
            <Field id="grant-hooks" label="Hooks" help="grant.hooks" optional>
              <QueryField label="hooks" q={hooksQ}>
                {hooks.length ? (
                  <div className="grid gap-2">
                    <ChipSet
                      id="grant-hooks"
                      aria-label="Hooks"
                      value={hookIds}
                      onChange={setHookIds}
                      options={hooks.map((h) => ({ value: h.id, label: h.name, hint: PHASE_LABEL[h.phase] }))}
                    />
                    {hookIds.length > 0 && (
                      <ol aria-label="Hook run order" className="grid gap-1">
                        {hookIds.map((hid, i) => {
                          const h = hooks.find((x) => x.id === hid);
                          const name = h?.name ?? hid;
                          return (
                            <li key={hid} className="flex min-h-9 items-center gap-2 rounded-md border border-border px-2 text-sm">
                              <span className="w-5 text-right tabular-nums text-ink-muted">{i + 1}.</span>
                              <span className="min-w-0 flex-1 truncate">{name}</span>
                              {h && <span className="text-xs text-ink-muted">{PHASE_LABEL[h.phase]}</span>}
                              {h?.kind === 'restart' && client.restartTargets.length > 0 && !client.restartTargets.some((t) => t.allowed && t.target === h.target) && (
                                <ToneChip tone="expiring" icon={TriangleAlert} label="Not allowed on this agent" title={`${h.target} is not in ${client.name}'s CF_RESTART_ALLOW`} />
                              )}
                              <IconButton variant="ghost" size="icon-sm" className="size-7" label={`Move ${name} up`} disabled={i === 0} onClick={() => moveHook(i, -1)}>
                                <ArrowUp className="size-3.5" aria-hidden />
                              </IconButton>
                              <IconButton
                                variant="ghost"
                                size="icon-sm"
                                className="size-7"
                                label={`Move ${name} down`}
                                disabled={i === hookIds.length - 1}
                                onClick={() => moveHook(i, 1)}
                              >
                                <ArrowDown className="size-3.5" aria-hidden />
                              </IconButton>
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-ink-muted">No hooks in this org.</p>
                )}
              </QueryField>
            </Field>
            <SwitchField
              id="grant-auto"
              label="Auto-remediate"
              help="grant.autoRemediate"
              checked={autoRemediate}
              onCheckedChange={setAutoRemediate}
              onText="Reinstall on drift"
              offText="Report only"
            />
          </FormSection>
          {failures.length > 0 && (
            <ul role="alert" aria-label="Not granted" className="grid gap-1 rounded-md border border-failed p-3 text-sm">
              {failures.map((f) => (
                <li key={f.certificateId}>{`${certName(f.certificateId)}: ${f.message}`}</li>
              ))}
            </ul>
          )}
          {formError && (
            <p role="alert" className="flex items-center gap-1 text-sm text-failed">
              <CircleAlert className="size-3.5 shrink-0" aria-hidden />
              {formError}
            </p>
          )}
        </div>
        )}
        <SheetFooter className="flex-row justify-end gap-2">
          <SheetClose asChild>
            <Button variant="outline">Cancel</Button>
          </SheetClose>
          <PermissionTip allowed={!keyBlocked && !removed} action="keys:export" reason={removed ? 'This grant was removed' : undefined}>
            <Button disabled={busy || keyBlocked || removed} onClick={() => void submit()}>
              {editing ? 'Save' : 'Grant'}
            </Button>
          </PermissionTip>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
