import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import type { UploadFieldErrors } from './UploadFields';

export type UploadFieldName = keyof UploadFieldErrors;
const FIELD_NAMES: readonly string[] = ['certificatePem', 'privateKeyPem', 'pkcs12Base64', 'password'];

/** Whether `field` is one of `UploadFields`' own fields — the caller still
 * has to check this itself (Upload's own Name isn't one, and routes there
 * instead; see `uploadErrorOutcome`'s own doc comment). */
export function isUploadFieldName(field: string): field is UploadFieldName {
  return FIELD_NAMES.includes(field);
}

export type UploadErrorOutcome =
  | { kind: 'field'; field: string; message: string }
  | { kind: 'conflict'; message: string }
  | { kind: 'form'; message: string };

/** Fix round 1 (review, Important): the same 422/409/413 mapping used to be
 * hand-rolled in both UploadPage (full certificate upload) and
 * UploadVersionSheet (version upload onto an unmanaged certificate) — one
 * implementation now, called from both.
 *
 * A 422 routes to the field its title names, whatever that field is — the
 * caller decides what to do with one it doesn't render itself (Upload's own
 * Name field isn't part of `UploadFields` at all, so it checks
 * `isUploadFieldName` itself and falls back to its own Name error state).
 * A 409 is a conflict; each caller places it wherever its own form shows one
 * (Upload's Name field for "already exists", UploadVersionSheet's form alert
 * for "managed externally" or a grant needing a key). A 413 is the server's
 * 1 MiB JSON body cap, translated to the same message regardless of what the
 * server actually sent. Anything else falls back to a generic form message. */
export function uploadErrorOutcome(e: unknown): UploadErrorOutcome {
  if (e instanceof ApiError && e.status === 422) {
    const field = fieldOfTitle(e.problem.title);
    if (field) return { kind: 'field', field, message: e.problem.detail ?? e.message };
  }
  if (e instanceof ApiError && e.status === 409) {
    return { kind: 'conflict', message: e.problem.detail ?? e.message };
  }
  if (e instanceof ApiError && e.status === 413) {
    return { kind: 'form', message: 'Larger than 1 MiB.' };
  }
  return { kind: 'form', message: errorMessage(e) };
}
