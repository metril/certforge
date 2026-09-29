import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { allCertificatesQuery, plural } from '@/api/queries/certificates';
import { layoutsQuery } from '@/api/queries/delivery';
import { useCreateServerGrant, useUpdateGrant } from '@/api/queries/grants';
import type { Grant, GrantUpdate } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { Button } from '@/components/ui/button';

type Props = { orgId: string; targetId: string; editing?: Grant; onBack: () => void; onDone: () => void };

// The Layout combobox's first, always-present option: picking it (or
// clearing the field) means layoutId: null, "use the target's own key
// names" (task-9-brief).
const NO_LAYOUT = '__target_files__';

export function ServerGrantForm({ orgId, targetId, editing, onBack, onDone }: Props) {
  const certsQ = useQuery(allCertificatesQuery(orgId));
  const layoutsQ = useQuery(layoutsQuery(orgId));
  const create = useCreateServerGrant(orgId, targetId);
  const update = useUpdateGrant(orgId);
  const [certificateId, setCertificateId] = useState<string | undefined>(editing?.certificateId);
  const [layoutId, setLayoutId] = useState<string | undefined>(editing?.layoutId ?? undefined);
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

  const submit = async () => {
    setCertError(null);
    setLayoutError(null);
    setFormError(null);
    if (!editing && !certificateId) {
      setCertError('Pick a certificate.');
      return;
    }
    try {
      if (editing) {
        // internal/api/grants.go's updateServerGrant only reads Body.LayoutId
        // for a server grant; the other GrantUpdate fields are agent-only and
        // ignored server-side, so they're not worth collecting here.
        await update.mutateAsync({ id: editing.id, body: { layoutId: layoutId ?? null } as GrantUpdate });
      } else {
        await create.mutateAsync({ certificateId: certificateId!, layoutId: layoutId ?? null });
      }
      onDone();
    } catch (e) {
      const field = e instanceof ApiError && e.status === 422 ? fieldOfTitle(e.problem.title) : null;
      if (field === 'certificateId') setCertError(errorMessage(e));
      else if (field === 'layoutId') setLayoutError(errorMessage(e));
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
