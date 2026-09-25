import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { BulkActionError } from '@/api/queries/certificates';

/**
 * The renew toast at every single-certificate call site ("Renew now" on
 * the Overview attention queue, "Renew `<name>`" in the command palette).
 * `useRenewCertificates` is `meta: { silent: true }` (Task 11: bulk renew
 * shows its own toast naming exactly which certificates failed instead of
 * the mutation cache's generic one), so a single-certificate call site
 * needs the same pair of handlers Task 11's bulk renew passes, not the
 * cache's default.
 *
 * `settleBulk` (api/queries/certificates.ts) only ever throws
 * `BulkActionError` — never a bare `ApiError` — so a failure is always
 * that type here; naming the certificate directly (like Task 11's
 * `bulkFailureMessage` names each failed row) reads better than
 * `errorMessage`'s generic "All 1 certificate failed." `errorMessage` is
 * still the fallback for anything else that could reach `onError`.
 */
export function renewToastHandlers(name: string) {
  return {
    onSuccess: () => toast.success(`Renewal queued for ${name}`),
    onError: (err: unknown) => toast.error(err instanceof BulkActionError ? `Renewal failed for ${name}.` : errorMessage(err)),
  };
}
