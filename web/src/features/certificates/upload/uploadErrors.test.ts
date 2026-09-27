import { describe, expect, it } from 'vitest';
import { ApiError } from '@/api/errors';
import { isUploadFieldName, uploadErrorOutcome } from './uploadErrors';

// Fix round 1 (review, Important): UploadPage and UploadVersionSheet both
// hand-rolled the same 422/409/413 mapping. This is the one shared
// implementation both now call.
describe('uploadErrorOutcome', () => {
  it('routes a 422 naming a rendered upload field to that field', () => {
    const e = new ApiError(422, { title: 'Invalid privateKeyPem', detail: "Doesn't match the certificate." });
    expect(uploadErrorOutcome(e)).toEqual({ kind: 'field', field: 'privateKeyPem', message: "Doesn't match the certificate." });
  });

  it("routes a 422 naming a field the caller doesn't render itself (e.g. Upload's own Name) the same way, leaving the caller to place it", () => {
    const e = new ApiError(422, { title: 'Invalid name', detail: 'Already taken.' });
    expect(uploadErrorOutcome(e)).toEqual({ kind: 'field', field: 'name', message: 'Already taken.' });
  });

  it('falls back to the title when a 422 has no detail', () => {
    const e = new ApiError(422, { title: 'Invalid password' });
    expect(uploadErrorOutcome(e)).toEqual({ kind: 'field', field: 'password', message: 'Invalid password' });
  });

  it('surfaces a 409 as a conflict, for the caller to place (Name for Upload, a form alert for version upload)', () => {
    const e = new ApiError(409, { detail: 'A certificate named legacy-api already exists.' });
    expect(uploadErrorOutcome(e)).toEqual({ kind: 'conflict', message: 'A certificate named legacy-api already exists.' });
  });

  it('maps a 413 to the browser-side size-cap message, ignoring whatever the server sent', () => {
    const e = new ApiError(413, { detail: 'Payload too large' });
    expect(uploadErrorOutcome(e)).toEqual({ kind: 'form', message: 'Larger than 1 MiB.' });
  });

  it('falls back to a generic form message for anything else', () => {
    expect(uploadErrorOutcome(new ApiError(500, { detail: 'boom' }))).toEqual({ kind: 'form', message: 'boom' });
    expect(uploadErrorOutcome(new Error('offline'))).toEqual({ kind: 'form', message: 'offline' });
  });
});

describe('isUploadFieldName', () => {
  it('accepts exactly the fields UploadFields renders', () => {
    expect(isUploadFieldName('certificatePem')).toBe(true);
    expect(isUploadFieldName('privateKeyPem')).toBe(true);
    expect(isUploadFieldName('pkcs12Base64')).toBe(true);
    expect(isUploadFieldName('password')).toBe(true);
  });

  it('rejects a field it does not render (e.g. name)', () => {
    expect(isUploadFieldName('name')).toBe(false);
  });
});
