import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { allCertificatesPickerQuery, plural } from '@/api/queries/certificates';
import { deployTargetsQuery, layoutsQuery } from '@/api/queries/delivery';
import { grantPfSenseUsageQuery, useCreateServerGrant, useUpdateGrant } from '@/api/queries/grants';
import type { Grant, GrantUpdate, PostAction } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { FormSection } from '@/components/FormSection';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

import { verifyDefault } from './verifyDefault';

type Props = { orgId: string; targetId: string; editing?: Grant; onBack: () => void; onDone: () => void };

// The Layout combobox's first, always-present option: picking it (or
// clearing the field) means layoutId: null, "use the target's own key
// names" (task-9-brief).
const NO_LAYOUT = '__target_files__';

type PostKind = 'ssh' | 'pfsense';
// What the pfSense kind prefills: restarts the WebGUI so it picks up the new certificate.
const PFSENSE_COMMAND = '/etc/rc.restart_webgui';
const KIND_LABEL: Record<PostKind, string> = { ssh: 'SSH', pfsense: 'pfSense' };

type RestartMode = 'all' | 'selected' | 'none';
type StoredRestart = { mode?: RestartMode; services?: string[] };
const NOT_IN_USE = ' (not in use)';

function storedRestart(g?: Grant): StoredRestart | undefined {
  const r = g?.targetOptions?.pfsenseRestart;
  return r && typeof r === 'object' ? (r as StoredRestart) : undefined;
}

export function ServerGrantForm({ orgId, targetId, editing, onBack, onDone }: Props) {
  const certsQ = useQuery(allCertificatesPickerQuery(orgId));
  const layoutsQ = useQuery(layoutsQuery(orgId));
  const targetsQ = useQuery(deployTargetsQuery(orgId));
  const create = useCreateServerGrant(orgId, targetId);
  const update = useUpdateGrant(orgId);
  const [certificateId, setCertificateId] = useState<string | undefined>(editing?.certificateId);
  const [layoutId, setLayoutId] = useState<string | undefined>(editing?.layoutId ?? undefined);
  const [postOn, setPostOn] = useState(!!editing?.postAction);
  const [kind, setKind] = useState<PostKind>(editing?.postAction?.kind ?? 'ssh');
  const [postTargetId, setPostTargetId] = useState<string | undefined>(editing?.postAction?.targetId);
  const [command, setCommand] = useState(editing?.postAction?.command ?? '');
  const [timeout, setTimeoutSeconds] = useState(String(editing?.postAction?.timeoutSeconds ?? 60));
  const [postError, setPostError] = useState<string | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [layoutError, setLayoutError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const target = targetsQ.data?.find((t) => t.id === targetId);
  const vDef = verifyDefault(target);
  const [verifyOn, setVerifyOn] = useState<boolean | undefined>(editing ? !!editing.verify : undefined);
  const [hostEdit, setHostEdit] = useState<string | undefined>(undefined);
  const [portEdit, setPortEdit] = useState<string | undefined>(undefined);
  const [sniEdit, setSniEdit] = useState<string | undefined>(undefined);
  const [autoRemediate, setAutoRemediate] = useState(editing?.autoRemediate ?? false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const vHost = hostEdit ?? editing?.verify?.host ?? vDef?.host ?? '';
  const vPort = portEdit ?? String(editing?.verify?.port ?? vDef?.port ?? '443');
  const vSni = sniEdit ?? editing?.verify?.sni ?? '';
  const vOn = vDef ? (verifyOn ?? vHost !== '') : false;
  const isPf = targetsQ.data?.find((t) => t.id === targetId)?.type === 'pfsense';
  const stored = storedRestart(editing);
  const [pickedMode, setRestartMode] = useState<RestartMode | undefined>(undefined);
  const targetDefault: RestartMode = targetsQ.data?.find((t) => t.id === targetId)?.config?.restartServices === false ? 'none' : 'all';
  const restartMode: RestartMode = pickedMode ?? stored?.mode ?? targetDefault;
  const inherited = !stored && pickedMode === undefined;
  const [restartKeys, setRestartKeys] = useState<string[]>(stored?.services ?? []);
  const [restartError, setRestartError] = useState<string | null>(null);
  // Never fetched on its own (enabled: false): "Only these" asks the firewall once.
  const usageQ = useQuery(grantPfSenseUsageQuery(orgId, editing?.id ?? ''));
  const wantUsage = isPf && !!editing && restartMode === 'selected';
  const { refetch: loadUsage } = usageQ;
  const usageLoaded = usageQ.data !== undefined;
  useEffect(() => {
    if (wantUsage && !usageLoaded) void loadUsage();
  }, [wantUsage, usageLoaded, loadUsage]);
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

  const postTargetOptions = (targetsQ.data ?? []).filter((t) => t.type === kind).map((t) => ({ value: t.id, label: t.name }));

  const changeKind = (next: PostKind) => {
    if (next === kind) return;
    setKind(next);
    setPostTargetId(undefined);
    setPostError(null);
    if (next === 'pfsense' && !command.trim()) setCommand(PFSENSE_COMMAND);
    else if (next === 'ssh' && command.trim() === PFSENSE_COMMAND) setCommand('');
  };

  const usage = usageQ.data;
  const reported = usage?.services ?? [];
  const reportedKeys = new Set(reported.map((x) => x.key));
  const restartOptions = [
    ...reported.map((x) => ({ value: x.key, label: x.label })),
    ...(usage ? restartKeys.filter((k) => !reportedKeys.has(k)).map((k) => ({ value: k, label: k + NOT_IN_USE })) : []),
  ];

  const submit = async () => {
    setRestartError(null);
    setPostError(null);
    setCertError(null);
    setLayoutError(null);
    setFormError(null);
    setVerifyError(null);
    let verify: { host: string; port: number; sni?: string; intervalSeconds: number } | null = null;
    if (vOn) {
      const port = Number(vPort);
      if (!vHost.trim() || !Number.isInteger(port) || port < 1 || port > 65535) {
        setVerifyError('Enter a host and a port from 1 to 65535.');
        return;
      }
      verify = { host: vHost.trim(), port, intervalSeconds: editing?.verify?.intervalSeconds ?? 3600, ...(vSni.trim() && { sni: vSni.trim() }) };
    }
    if (!editing && !certificateId) {
      setCertError('Pick a certificate.');
      return;
    }
    if (isPf && restartMode === 'selected' && restartKeys.length === 0) {
      setRestartError('Pick at least one service, or choose None.');
      return;
    }
    // "All that use it" on a grant that never chose is left unset, so it keeps following the target's option.
    const targetOptions: Record<string, unknown> | undefined = !isPf
      ? undefined
      : restartMode === 'selected'
        ? { pfsenseRestart: { mode: 'selected', services: restartKeys } }
        : inherited
          ? {}
          : { pfsenseRestart: { mode: restartMode } };
    let postAction: PostAction | undefined;
    if (postOn) {
      const secs = Number(timeout);
      if (!postTargetId || !command.trim()) {
        setPostError(`Pick a${kind === 'ssh' ? 'n SSH' : ' pfSense'} target and enter a command.`);
        return;
      }
      if (!Number.isInteger(secs) || secs < 5 || secs > 300) {
        setPostError('Timeout must be 5 to 300 seconds.');
        return;
      }
      postAction = { kind, targetId: postTargetId, command: command.trim(), timeoutSeconds: secs };
    }
    try {
      if (editing) {
        // internal/api/grants.go's updateServerGrant only reads LayoutId and
        // PostAction for a server grant; the other GrantUpdate fields are
        // agent-only and ignored server-side. Omitting postAction clears it.
        await update.mutateAsync({ id: editing.id, body: { layoutId: layoutId ?? null, autoRemediate: vOn && autoRemediate, verify, ...(targetOptions && { targetOptions }), ...(postAction && { postAction }) } as GrantUpdate });
      } else {
        await create.mutateAsync({ certificateId: certificateId!, autoRemediate: vOn && autoRemediate, layoutId: layoutId ?? null, ...(verify && { verify }), ...(targetOptions && Object.keys(targetOptions).length > 0 && { targetOptions }), ...(postAction && { postAction }) });
      }
      onDone();
    } catch (e) {
      const field = e instanceof ApiError && e.status === 422 ? fieldOfTitle(e.problem.title) : null;
      if (field === 'certificateId') setCertError(errorMessage(e));
      else if (field === 'layoutId') setLayoutError(errorMessage(e));
      else if (field === 'postAction') setPostError(errorMessage(e));
      else if (field === 'targetOptions') setRestartError(errorMessage(e));
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
      {isPf && (
        <Field id="server-grant-restart" label="Restart services" help="grant.pfsenseRestart" error={restartError}>
          <div className="grid gap-2">
            <SegmentedControl<RestartMode>
              id="server-grant-restart"
              aria-label="Restart services"
              value={restartMode}
              onChange={(m) => {
                setRestartMode(m);
                setRestartError(null);
              }}
              options={[
                { value: 'all', label: 'All that use it' },
                { value: 'selected', label: 'Only these', disabled: !editing, hint: editing ? undefined : 'The service list is available after the first deploy.' },
                { value: 'none', label: 'None' },
              ]}
            />
            {inherited && <p className="text-xs text-ink-muted">(target default)</p>}
            {!editing && <p className="text-xs text-ink-muted">Choosing services is available after the first deploy; until then every service that uses the certificate restarts.</p>}
            {restartMode === 'selected' && editing && (
              <div className="grid gap-1.5">
                {usageQ.isError ? (
                  <p role="alert" className="text-xs text-failed">
                    {errorMessage(usageQ.error)}
                  </p>
                ) : usageQ.isFetching && !usage ? (
                  <p className="text-xs text-ink-muted">Asking the firewall…</p>
                ) : usage && usage.refid === null ? (
                  <p className="text-xs text-ink-muted">The certificate is not on the firewall yet.</p>
                ) : null}
                {restartOptions.length > 0 && <ChipSet aria-label="Services to restart" value={restartKeys} onChange={setRestartKeys} options={restartOptions} />}
                {usage && usage.refid !== null && restartOptions.length === 0 && <p className="text-xs text-ink-muted">No services use it.</p>}
              </div>
            )}
          </div>
        </Field>
      )}
      <div className="grid gap-3">
        <SwitchField id="server-grant-post" label="Post action" help="grant.postAction" checked={postOn} onCheckedChange={setPostOn} onText="Run a command after deploy" offText="None" />
        {postOn && (
          <>
            <Field id="server-grant-post-kind" label="Kind" help="grant.postActionKind">
              <SegmentedControl<PostKind>
                id="server-grant-post-kind"
                aria-label="Post action kind"
                value={kind}
                onChange={changeKind}
                options={[
                  { value: 'ssh', label: 'SSH' },
                  { value: 'pfsense', label: 'pfSense' },
                ]}
              />
            </Field>
            <Field id="server-grant-post-target" label={`${KIND_LABEL[kind]} target`} error={postError}>
              <Combobox
                id="server-grant-post-target"
                aria-label={`${KIND_LABEL[kind]} target`}
                value={postTargetId}
                onChange={(v) => {
                  setPostTargetId(v);
                  setPostError(null);
                }}
                options={postTargetOptions}
                placeholder={`Pick a${kind === 'ssh' ? 'n SSH' : ' pfSense'} target`}
                emptyText={`No ${KIND_LABEL[kind]} targets yet.`}
              />
            </Field>
            <Field id="server-grant-post-command" label="Command">
              <Input id="server-grant-post-command" className="font-mono" maxLength={512} value={command} onChange={(e) => setCommand(e.target.value)} />
            </Field>
            <Field id="server-grant-post-timeout" label="Timeout (seconds)">
              <Input id="server-grant-post-timeout" type="number" min={5} max={300} value={timeout} onChange={(e) => setTimeoutSeconds(e.target.value)} />
            </Field>
          </>
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
