import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { allCertificatesPickerQuery, plural } from '@/api/queries/certificates';
import { deployTargetsQuery, layoutsQuery } from '@/api/queries/delivery';
import { useCreateServerGrant, useUpdateGrant } from '@/api/queries/grants';
import type { Grant, GrantUpdate, PostAction } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type Props = { orgId: string; targetId: string; editing?: Grant; onBack: () => void; onDone: () => void };

// The Layout combobox's first, always-present option: picking it (or
// clearing the field) means layoutId: null, "use the target's own key
// names" (task-9-brief).
const NO_LAYOUT = '__target_files__';

type PostKind = 'ssh' | 'pfsense';
// What the pfSense kind prefills: restarts the WebGUI so it picks up the new certificate.
const PFSENSE_COMMAND = '/etc/rc.restart_webgui';
const KIND_LABEL: Record<PostKind, string> = { ssh: 'SSH', pfsense: 'pfSense' };

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

  const submit = async () => {
    setPostError(null);
    setCertError(null);
    setLayoutError(null);
    setFormError(null);
    if (!editing && !certificateId) {
      setCertError('Pick a certificate.');
      return;
    }
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
        await update.mutateAsync({ id: editing.id, body: { layoutId: layoutId ?? null, ...(postAction && { postAction }) } as GrantUpdate });
      } else {
        await create.mutateAsync({ certificateId: certificateId!, layoutId: layoutId ?? null, ...(postAction && { postAction }) });
      }
      onDone();
    } catch (e) {
      const field = e instanceof ApiError && e.status === 422 ? fieldOfTitle(e.problem.title) : null;
      if (field === 'certificateId') setCertError(errorMessage(e));
      else if (field === 'layoutId') setLayoutError(errorMessage(e));
      else if (field === 'postAction') setPostError(errorMessage(e));
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
        <Button type="button" disabled={busy} onClick={() => void submit()}>
          {editing ? 'Save' : 'Grant'}
        </Button>
      </div>
    </div>
  );
}
