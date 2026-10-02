import { Card } from '@/components/Card';
import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { useUploadCertificate } from '@/api/queries/certificates';
import { Field } from '@/components/Field';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { UploadFields, type UploadFieldErrors } from './UploadFields';
import { emptyUploadValue, p12TooLarge, toUploadBody, type UploadValue } from './uploadBody';
import { isUploadFieldName, uploadErrorOutcome } from './uploadErrors';

export function UploadPage() {
  const org = useOrg();
  const me = useMe();
  const navigate = useNavigate();
  const canWrite = can(me, 'certs:write', org.id);
  const upload = useUploadCertificate(org.id);

  const [name, setName] = useState('');
  const [value, setValue] = useState<UploadValue>(emptyUploadValue);
  const [nameError, setNameError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<UploadFieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);

  // Fix round 1 (review, Important): `ready` used to ignore `name`, so
  // Upload stayed enabled with a blank Name and `submit`'s own guard
  // silently no-opped on click instead of visibly refusing.
  const ready =
    name.trim() !== '' && (value.format === 'pem' ? value.certificatePem.trim() !== '' : !!value.file && !p12TooLarge(value.file));

  async function submit() {
    setNameError(null);
    setFieldErrors({});
    setFormError(null);
    if (!name.trim() || !ready) return;
    try {
      const cert = await upload.mutateAsync({ name: name.trim(), ...(await toUploadBody(value)) });
      toast.success(`Uploaded ${cert.name}`);
      await navigate({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id: cert.id, tab: 'overview' } });
    } catch (e) {
      const outcome = uploadErrorOutcome(e);
      if (outcome.kind === 'field') {
        if (outcome.field === 'name') {
          setNameError(outcome.message);
          return;
        }
        if (isUploadFieldName(outcome.field)) {
          setFieldErrors({ [outcome.field]: outcome.message });
          return;
        }
      }
      if (outcome.kind === 'conflict') {
        setNameError(outcome.message);
        return;
      }
      setFormError(outcome.message);
    }
  }

  return (
    <div className="grid max-w-[720px] gap-6">
      <nav aria-label="Breadcrumb" className="text-sm">
        <Link to="/o/$org/certificates" params={{ org: org.slug }} className="text-ink-muted hover:text-ink">
          Certificates
        </Link>
      </nav>
      <PageHeader title="Upload certificate" />
      <Card className="grid gap-5 p-4">
        <Field id="upload-name" label="Name" error={nameError}>
          <Input
            id="upload-name"
            placeholder="legacy-api"
            autoComplete="off"
            disabled={!canWrite}
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setNameError(null);
            }}
          />
        </Field>
        <UploadFields value={value} onChange={setValue} errors={fieldErrors} disabled={!canWrite} />
        {formError && (
          <p role="alert" className="text-sm">
            {formError}
          </p>
        )}
        <div className="flex items-center gap-2">
          <Button variant="outline" asChild>
            <Link to="/o/$org/certificates" params={{ org: org.slug }}>
              Cancel
            </Link>
          </Button>
          <PermissionTip allowed={canWrite} action="certs:write">
            <Button disabled={!canWrite || !ready || upload.isPending} onClick={() => void submit()}>
              {upload.isPending ? 'Uploading…' : 'Upload'}
            </Button>
          </PermissionTip>
        </div>
      </Card>
    </div>
  );
}
