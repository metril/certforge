import { useState } from 'react';
import { toast } from 'sonner';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { useUploadVersion } from '@/api/queries/certificates';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { UploadFields, type UploadFieldErrors } from '@/features/certificates/upload/UploadFields';
import { emptyUploadValue, p12TooLarge, toUploadBody, type UploadValue } from '@/features/certificates/upload/uploadBody';

type UploadFieldName = keyof UploadFieldErrors;
const FIELD_NAMES: readonly string[] = ['certificatePem', 'privateKeyPem', 'pkcs12Base64', 'password'];
function isUploadFieldName(field: string): field is UploadFieldName {
  return FIELD_NAMES.includes(field);
}

type Props = { orgId: string; id: string; onOpenChange: (open: boolean) => void };

/** Task 7: adds a version to an unmanaged certificate — the header's
 * "Upload new version" action. Reuses Task 5's UploadFields (uploadBody's
 * UploadValue/toUploadBody are shared for exactly this) without a Name
 * field, since the certificate already has one. */
export function UploadVersionSheet({ orgId, id, onOpenChange }: Props) {
  const upload = useUploadVersion(orgId, id);
  const [value, setValue] = useState<UploadValue>(emptyUploadValue);
  const [fieldErrors, setFieldErrors] = useState<UploadFieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);

  const ready = value.format === 'pem' ? value.certificatePem.trim() !== '' : !!value.file && !p12TooLarge(value.file);

  async function submit() {
    setFieldErrors({});
    setFormError(null);
    if (!ready) return;
    try {
      await upload.mutateAsync(await toUploadBody(value));
      toast.success('New version uploaded');
      onOpenChange(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        const field = fieldOfTitle(e.problem.title);
        const detail = e.problem.detail ?? e.message;
        if (field && isUploadFieldName(field)) {
          setFieldErrors({ [field]: detail });
          return;
        }
      }
      // 409: either the certificate is managed (raced) or a grant needing
      // this certificate's key can't take a keyless version — either way
      // the server's own message names the reason.
      if (e instanceof ApiError && e.status === 409) {
        setFormError(e.problem.detail ?? e.message);
        return;
      }
      if (e instanceof ApiError && e.status === 413) {
        setFormError('Larger than 1 MiB.');
        return;
      }
      setFormError(errorMessage(e));
    }
  }

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Upload new version</SheetTitle>
          <SheetDescription className="sr-only">Add a new version to this certificate</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <div className="flex items-center gap-1.5 text-sm text-ink-muted">
            Becomes the current version
            <HelpTip id="cert.uploadVersion" />
          </div>
          <UploadFields value={value} onChange={setValue} errors={fieldErrors} disabled={upload.isPending} />
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
          <Button disabled={!ready || upload.isPending} onClick={() => void submit()}>
            {upload.isPending ? 'Uploading…' : 'Upload'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
