import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { useRevokeVersion } from '@/api/queries/certificates';
import type { CertificateVersion, RevocationReason } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { Field } from '@/components/Field';

const REASONS: { value: RevocationReason; label: string }[] = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'keyCompromise', label: 'Key compromise' },
  { value: 'caCompromise', label: 'CA compromise' },
  { value: 'affiliationChanged', label: 'Affiliation changed' },
  { value: 'superseded', label: 'Superseded' },
  { value: 'cessationOfOperation', label: 'Ceased operation' },
];

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  orgId: string;
  certId: string;
  version: CertificateVersion;
};

// useRevokeVersion (Task 1) is `meta: { silent: true, success: 'Version
// revoked' }`: the mutationCache shows the success toast itself, but an
// error never does — so 409 ("already revoked", the version raced a
// concurrent revoke) and 422 (not supported for this CA/version) are
// caught here and toasted explicitly, per the brief, instead of falling
// through to ConfirmDestructive's own inline banner (which would keep the
// dialog open on a conflict that's actually already resolved server-side).
export function RevokeVersionDialog({ open, onOpenChange, orgId, certId, version }: Props) {
  const [reason, setReason] = useState<RevocationReason>('unspecified');
  const qc = useQueryClient();
  const revoke = useRevokeVersion(orgId, certId);

  useEffect(() => {
    if (!open) setReason('unspecified');
  }, [open]);

  return (
    <ConfirmDestructive
      open={open}
      onOpenChange={onOpenChange}
      title={`Revoke version ${version.serial}?`}
      consequence="It is listed on the CA's CRL and cannot be undone."
      confirmText="Revoke"
      actionLabel="Revoke"
      onConfirm={async () => {
        try {
          await revoke.mutateAsync({ vid: version.id, reason });
        } catch (e) {
          if (e instanceof ApiError && e.status === 409) {
            toast.error('Already revoked');
            // Batch 2 review (Important): the version raced someone else's
            // revoke, which already bumped the CA's revokedCount — refresh
            // both, same as the success path.
            void qc.invalidateQueries({ queryKey: ['versions', orgId, certId] });
            void qc.invalidateQueries({ queryKey: ['cas', orgId] });
            return;
          }
          if (e instanceof ApiError && e.status === 422) {
            toast.error(errorMessage(e));
            return;
          }
          throw e;
        }
      }}
    >
      <Field id="revoke-reason" label="Reason" help="version.revokeReason">
        <Combobox
          id="revoke-reason"
          aria-label="Reason"
          value={reason}
          onChange={(v) => setReason((v as RevocationReason | undefined) ?? 'unspecified')}
          options={REASONS}
          placeholder="Unspecified"
          emptyText="No reasons."
        />
      </Field>
    </ConfirmDestructive>
  );
}
