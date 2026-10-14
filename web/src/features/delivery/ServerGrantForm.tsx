import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { allCertificatesPickerQuery, plural } from '@/api/queries/certificates';
import { actionGroupsQuery, actionsQuery, deployTargetsQuery, layoutsQuery } from '@/api/queries/delivery';
import { useCreateServerGrant, useUpdateGrant } from '@/api/queries/grants';
import type { Grant, GrantStep, GrantUpdate } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { FormSection } from '@/components/FormSection';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

import { DELAYS, INTERVALS, fmtDelay, fmtInterval } from '@/lib/monitors';
import { StepsPicker } from './StepsPicker';
import { verifyDefault } from './verifyDefault';

type Props = { orgId: string; orgSlug?: string; targetId: string; editing?: Grant; onBack: () => void; onDone: () => void };

// The Layout combobox's first, always-present option: picking it (or
// clearing the field) means layoutId: null, "use the target's own key
// names" (task-9-brief).
const NO_LAYOUT = '__target_files__';

export function ServerGrantForm({ orgId, orgSlug, targetId, editing, onBack, onDone }: Props) {
  const certsQ = useQuery(allCertificatesPickerQuery(orgId));
  const layoutsQ = useQuery(layoutsQuery(orgId));
  const targetsQ = useQuery(deployTargetsQuery(orgId));
  const actionsQ = useQuery(actionsQuery(orgId));
  const groupsQ = useQuery(actionGroupsQuery(orgId));
  const create = useCreateServerGrant(orgId, targetId);
  const update = useUpdateGrant(orgId);
  const [certificateId, setCertificateId] = useState<string | undefined>(editing?.certificateId);
  const [layoutId, setLayoutId] = useState<string | undefined>(editing?.layoutId ?? undefined);
  const [steps, setSteps] = useState<GrantStep[]>(editing?.steps ?? []);
  const [stepsError, setStepsError] = useState<string | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [layoutError, setLayoutError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const target = targetsQ.data?.find((t) => t.id === targetId);
  const vDef = verifyDefault(target);
  const restartKind = target?.type === 'pikvm' ? 'pikvm_restart' : target?.type === 'pfsense' ? 'pfsense_restart' : null;
  const kindOf = new Map((actionsQ.data ?? []).map((a) => [a.id, a.kind]));
  const groupIds = new Map((groupsQ.data ?? []).map((g) => [g.id, g.actionIds]));
  const hasRestart = steps.some((st) => ('action' in st ? [st.action] : (groupIds.get(st.group) ?? [])).some((id) => kindOf.get(id) === restartKind));
  const showRestartHint = !!restartKind && actionsQ.isSuccess && groupsQ.isSuccess && !hasRestart;
  const [verifyOn, setVerifyOn] = useState<boolean | undefined>(editing ? !!editing.verify : undefined);
  const [hostEdit, setHostEdit] = useState<string | undefined>(undefined);
  const [portEdit, setPortEdit] = useState<string | undefined>(undefined);
  const [sniEdit, setSniEdit] = useState<string | undefined>(undefined);
  const [autoRemediate, setAutoRemediate] = useState(editing?.autoRemediate ?? false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const vHost = hostEdit ?? editing?.verify?.host ?? vDef?.host ?? '';
  const vPort = portEdit ?? String(editing?.verify?.port ?? vDef?.port ?? '443');
  const [intervalEdit, setIntervalEdit] = useState<number | undefined>(undefined);
  const vInterval = intervalEdit ?? editing?.verify?.intervalSeconds ?? 3600;
  const [delayEdit, setDelayEdit] = useState<number | undefined>(undefined);
  const vDelay = delayEdit ?? editing?.verify?.postDeployDelaySeconds ?? 15;
  const vSni = sniEdit ?? editing?.verify?.sni ?? '';
  const vOn = vDef ? (verifyOn ?? vHost !== '') : false;
  const busy = create.isPending || update.isPending;

  // Only a certificate with a current version can be granted (task-9-brief).
  const certOptions = (certsQ.data ?? []).filter((c) => c.currentVersion).map((c) => ({ value: c.id, label: c.name, hint: c.commonName }));
  const layoutOptions = [
    { value: NO_LAYOUT, label: 'Target files' },
    ...(layoutsQ.data ?? []).map((l) => {
      const nonPem = l.files.some((f) => f.format !== 'pem');
      return { value: l.id, label: l.name, disabled: nonPem, hint: nonPem ? 'PEM layouts only' : plural(l.files.length, 'file') };
    }),
  ];

  const submit = async () => {
    setStepsError(null);
    setCertError(null);
    setLayoutError(null);
    setFormError(null);
    setVerifyError(null);
    let verify: { host: string; port: number; sni?: string; intervalSeconds: number; postDeployDelaySeconds: number } | null = null;
    if (vOn) {
      const port = Number(vPort);
      if (!vHost.trim() || !Number.isInteger(port) || port < 1 || port > 65535) {
        setVerifyError('Enter a host and a port from 1 to 65535.');
        return;
      }
      verify = { host: vHost.trim(), port, intervalSeconds: vInterval, postDeployDelaySeconds: vDelay, ...(vSni.trim() && { sni: vSni.trim() }) };
    }
    if (!editing && !certificateId) {
      setCertError('Pick a certificate.');
      return;
    }
    try {
      if (editing) {
        // updateServerGrant reads layoutId, steps, verify and autoRemediate for a server grant.
        await update.mutateAsync({ id: editing.id, body: { layoutId: layoutId ?? null, autoRemediate: vOn && autoRemediate, verify, steps } as GrantUpdate });
      } else {
        await create.mutateAsync({ certificateId: certificateId!, autoRemediate: vOn && autoRemediate, layoutId: layoutId ?? null, ...(verify && { verify }), steps });
      }
      onDone();
    } catch (e) {
      const field = e instanceof ApiError && e.status === 422 ? fieldOfTitle(e.problem.title) : null;
      if (field === 'certificateId') setCertError(errorMessage(e));
      else if (field === 'layoutId') setLayoutError(errorMessage(e));
      else if (field === 'steps') setStepsError(errorMessage(e));
      else setFormError(errorMessage(e));
    }
  };

  return (
    <div className="grid gap-5">
      <Field id="server-grant-cert" label="Certificate" error={certError}>
        <Combobox
          id="server-grant-cert"
          aria-label="Certificate"
          value={certificateId}
          onChange={(v) => {
            setCertificateId(v);
            setCertError(null);
          }}
          options={certOptions}
          placeholder="Pick a certificate"
          emptyText="No certificate with a current version."
          disabled={!!editing}
        />
      </Field>
      <Field id="server-grant-layout" label="Layout" help="grant.serverLayout" optional error={layoutError}>
        <Combobox
          id="server-grant-layout"
          aria-label="Layout"
          value={layoutId ?? NO_LAYOUT}
          onChange={(v) => {
            setLayoutId(v === NO_LAYOUT || !v ? undefined : v);
            setLayoutError(null);
          }}
          options={layoutOptions}
          placeholder="Target files"
          emptyText="No layouts yet."
        />
      </Field>
      <div className="grid gap-1.5">
        <StepsPicker orgId={orgId} runsOn="server" value={steps} onChange={setSteps} newActionHref={orgSlug ? `/o/${orgSlug}/delivery/actions?edit=new` : undefined} />
        {showRestartHint && (
          <p className="flex items-center gap-1 text-sm text-muted-foreground">
            No restart step: the device keeps serving its old certificate until something restarts the service.
            <HelpTip id="grant.restartStep" />
          </p>
        )}
        {stepsError && (
          <p role="alert" className="flex items-center gap-1 text-sm text-failed">
            <CircleAlert className="size-3.5 shrink-0" aria-hidden />
            {stepsError}
          </p>
        )}
      </div>
      {vDef && (
        <FormSection title="Verify" help="grant.verify">
          <SwitchField id="server-grant-verify" label="Verify the endpoint" help="grant.verify" checked={vOn} onCheckedChange={setVerifyOn} onText="Check the served certificate" offText="Off" />
          {vOn && (
            <>
              <Field id="server-grant-verify-host" label="Host" error={verifyError}>
                <Input id="server-grant-verify-host" className="font-mono" placeholder="pikvm.example" value={vHost} onChange={(e) => setHostEdit(e.target.value)} />
              </Field>
              <Field id="server-grant-verify-port" label="Port">
                <Input id="server-grant-verify-port" type="number" min={1} max={65535} value={vPort} onChange={(e) => setPortEdit(e.target.value)} />
              </Field>
              <Field id="server-grant-verify-sni" label="SNI" optional>
                <Input id="server-grant-verify-sni" className="font-mono" value={vSni} onChange={(e) => setSniEdit(e.target.value)} />
              </Field>
              <Field id="server-grant-verify-interval" label="Check every" help="grant.verifyInterval">
                <div className="grid gap-1">
                  <SegmentedControl
                    id="server-grant-verify-interval"
                    aria-label="Check every"
                    value={INTERVALS.some((i) => i.value === vInterval) ? String(vInterval) : ''}
                    onChange={(v) => setIntervalEdit(Number(v))}
                    options={INTERVALS.map((i) => ({ value: String(i.value), label: i.label }))}
                  />
                  {!INTERVALS.some((i) => i.value === vInterval) && <span className="text-xs text-ink-muted">Currently {fmtInterval(vInterval)}</span>}
                </div>
              </Field>
              <Field id="server-grant-verify-delay" label="Check after deploy" help="grant.verifyDelay">
                <div className="grid gap-1">
                  <SegmentedControl
                    id="server-grant-verify-delay"
                    aria-label="Check after deploy"
                    value={DELAYS.some((d) => d.value === vDelay) ? String(vDelay) : ''}
                    onChange={(v) => setDelayEdit(Number(v))}
                    options={DELAYS.map((d) => ({ value: String(d.value), label: d.label }))}
                  />
                  {!DELAYS.some((d) => d.value === vDelay) && <span className="text-xs text-ink-muted">Currently {fmtDelay(vDelay)}</span>}
                </div>
              </Field>
              <SwitchField id="server-grant-auto" label="Auto-remediate" help="grant.autoRemediateServer" checked={autoRemediate} onCheckedChange={setAutoRemediate} onText="Redeploy on drift" offText="Report only" />
            </>
          )}
        </FormSection>
      )}
      {formError && (
        <p role="alert" className="flex items-center gap-1 text-sm text-failed">
          <CircleAlert className="size-3.5 shrink-0" aria-hidden />
          {formError}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onBack}>
          Back
        </Button>
        {targetsQ.data ? (
          <Button type="button" disabled={busy} onClick={() => void submit()}>
            {editing ? 'Save' : 'Grant'}
          </Button>
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="inline-flex">
                <Button type="button" disabled>
                  {editing ? 'Save' : 'Grant'}
                </Button>
              </span>
            </TooltipTrigger>
            <TooltipContent>Loading targets…</TooltipContent>
          </Tooltip>
        )}
      </div>
    </div>
  );
}
