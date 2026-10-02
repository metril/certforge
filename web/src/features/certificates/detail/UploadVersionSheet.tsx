import { useDirty } from '@/lib/useDirty';
import { useState } from 'react';
import { toast } from 'sonner';
import { useUploadVersion } from '@/api/queries/certificates';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose, useSheetGuard } from '@/components/ui/sheet';
import { UploadFields, type UploadFieldErrors } from '@/features/certificates/upload/UploadFields';
import { emptyUploadValue, p12TooLarge, toUploadBody, type UploadValue } from '@/features/certificates/upload/uploadBody';
import { isUploadFieldName, uploadErrorOutcome } from '@/features/certificates/upload/uploadErrors';

type Props = { orgId: string; id: string; onOpenChange: (open: boolean) => void };

/** Task 7: adds a version to an unmanaged certificate — the header's
 * "Upload new version" action. Reuses Task 5's UploadFields (uploadBody's
 * UploadValue/toUploadBody are shared for exactly this) without a Name
 * field, since the certificate already has one. */
export function UploadVersionSheet({ orgId, id, onOpenChange }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const upload = useUploadVersion(orgId, id);
  const [value, setValue] = useState<UploadValue>(emptyUploadValue);
  const [fieldErrors, setFieldErrors] = useState<UploadFieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const dirty = useDirty({ ...value, file: value.file?.name ?? null });

  const ready = value.format === 'pem' ? value.certificatePem.trim() !== '' : !!value.file && !p12TooLarge(value.file);

  async function submit() {
    setFieldErrors({});
    setFormError(null);
    if (!ready) return;
    try {
      await upload.mutateAsync(await toUploadBody(value));
      toast.success('New version uploaded');
      guard.close();
    } catch (e) {
      const outcome = uploadErrorOutcome(e);
      // A 409 here is either the certificate is managed (raced) or a grant
      // needing this certificate's key can't take a keyless version — either
      // way the server's own message names the reason, so `conflict` (like
      // any field this sheet doesn't render) falls through to the form alert.
      if (outcome.kind === 'field' && isUploadFieldName(outcome.field)) {
        setFieldErrors({ [outcome.field]: outcome.message });
        return;
      }
      setFormError(outcome.message);
    }
  }

  return (
    <Sheet guard={guard} open form dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader className="flex-row items-center gap-1.5">
          <SheetTitle>Upload new version</SheetTitle>
          <HelpTip id="cert.uploadVersion" />
          <SheetDescription className="sr-only">Add a new version to this certificate</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <UploadFields value={value} onChange={setValue} errors={fieldErrors} disabled={upload.isPending} />
          {formError && (
            <p role="alert" className="text-sm">
              {formError}
            </p>
          )}
        </div>
        <SheetFooter className="flex-row justify-end gap-2">
          <SheetClose asChild>
            <Button variant="outline">Cancel</Button>
          </SheetClose>
          <Button disabled={!ready || upload.isPending} onClick={() => void submit()}>
            {upload.isPending ? 'Uploading…' : 'Upload'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
