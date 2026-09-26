import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { allCertificatesQuery, plural } from '@/api/queries/certificates';
import { deployTargetsQuery, hooksQuery, layoutsQuery } from '@/api/queries/delivery';
import { metaSchemasQuery } from '@/api/queries/dns';
import { useCreateGrants, useUpdateGrant, type GrantBatchResult } from '@/api/queries/grants';
import type { Client, Grant, GrantDelivery } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { MultiCombobox } from '@/components/MultiCombobox';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { PHASE_LABEL } from '@/lib/clientStatus';

type Props = { orgId: string; client: Client; grants: Grant[]; editing?: Grant; onOpenChange: (open: boolean) => void };

export function GrantSheet({ orgId, client, grants, editing, onOpenChange }: Props) {
  const certs = useQuery(allCertificatesQuery(orgId));
  const { data: layouts = [] } = useQuery(layoutsQuery(orgId));
  const { data: targets = [] } = useQuery(deployTargetsQuery(orgId));
  const { data: hooks = [] } = useQuery(hooksQuery(orgId));
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
  const busy = create.isPending || update.isPending;

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
    if (next.certs || next.where) return;
    const rest = { delivery, layoutId: layoutId ?? null, deployTargetId: targetId ?? null, hookIds, autoRemediate };
    if (editing) {
      try {
        await update.mutateAsync({ id: editing.id, body: rest });
        onOpenChange(false);
      } catch (e) {
        setFormError(errorMessage(e));
      }
      return;
    }
    const r = await create.mutateAsync({ certificateIds: certIds, rest });
    if (r.created.length > 0) toast.success(`Granted ${plural(r.created.length, 'certificate')}`);
    if (r.failed.length === 0) {
      onOpenChange(false);
      return;
    }
    setCertIds(r.failed.map((f) => f.certificateId));
    setFailures(r.failed);
  };

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{editing ? `Edit ${editing.certificateName}` : 'Grant certificate'}</SheetTitle>
          <SheetDescription className="sr-only">For client {client.name}</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          {editing ? (
            <div className="grid gap-1 text-sm">
              <span className="text-ink-muted">Certificate</span>
              <span className="font-semibold">{editing.certificateName}</span>
            </div>
          ) : (
            <Field id="grant-certs" label="Certificates" help="grant.certificates" error={errors.certs}>
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
                emptyText={certs.isPending ? 'Loading…' : 'No certificate to grant.'}
              />
            </Field>
          )}
          <Field id="grant-delivery" label="Delivery" help="grant.delivery">
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
          </Field>
          <Field id="grant-layout" label="Layout" help="grant.layout" optional>
            <Combobox
              id="grant-layout"
              aria-label="Layout"
              value={layoutId}
              onChange={(v) => {
                setLayoutId(v);
                setErrors((e) => ({ ...e, where: undefined }));
              }}
              options={layouts.map((l) => ({ value: l.id, label: l.name, hint: plural(l.files.length, 'file') }))}
              placeholder="No layout"
              emptyText="No layouts yet."
            />
          </Field>
          <Field id="grant-target" label="Deploy target" help="grant.target" optional error={errors.where}>
            <Combobox
              id="grant-target"
              aria-label="Deploy target"
              value={targetId}
              onChange={(v) => {
                setTargetId(v);
                setErrors((e) => ({ ...e, where: undefined }));
              }}
              options={targets.map((t) => ({ value: t.id, label: t.name, hint: typeName(t.type) }))}
              placeholder="No target"
              emptyText="No deploy targets yet."
            />
          </Field>
          <Field id="grant-hooks" label="Hooks" help="grant.hooks" optional>
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
                          <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Move ${name} up`} disabled={i === 0} onClick={() => moveHook(i, -1)}>
                            <ArrowUp className="size-3.5" aria-hidden />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            className="size-7"
                            aria-label={`Move ${name} down`}
                            disabled={i === hookIds.length - 1}
                            onClick={() => moveHook(i, 1)}
                          >
                            <ArrowDown className="size-3.5" aria-hidden />
                          </Button>
                        </li>
                      );
                    })}
                  </ol>
                )}
              </div>
            ) : (
              <p className="text-sm text-ink-muted">No hooks in this org.</p>
            )}
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
          {failures.length > 0 && (
            <ul role="alert" aria-label="Not granted" className="grid gap-1 rounded-md border border-failed p-3 text-sm">
              {failures.map((f) => (
                <li key={f.certificateId}>{`${certName(f.certificateId)}: ${f.message}`}</li>
              ))}
            </ul>
          )}
          {formError && (
            <p role="alert" className="text-sm">
              {formError}
            </p>
          )}
        </div>
        <SheetFooter className="flex-row justify-end gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={busy} onClick={() => void submit()}>
            {editing ? 'Save' : 'Grant'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
