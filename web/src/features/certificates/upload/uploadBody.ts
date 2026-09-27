import type { CertificateVersionUpload } from '@/api/types';
import { MAX_P12_BYTES, readBase64 } from '@/lib/files';

/** Shared by Task 7's version-upload sheet as well as UploadPage. */
export type UploadValue = {
  format: 'pem' | 'p12';
  certificatePem: string;
  privateKeyPem: string;
  file: File | null;
  password: string;
};

export const emptyUploadValue: UploadValue = { format: 'pem', certificatePem: '', privateKeyPem: '', file: null, password: '' };

/** Browser cap (global-constraints.md, Deviations): base64 inflates a P12
 * file by 4/3, and the server caps the JSON body at 1 MiB. */
export function p12TooLarge(file: File | null): boolean {
  return !!file && file.size > MAX_P12_BYTES;
}

/** Never sends both kinds: PEM sends certificatePem (+ privateKeyPem when
 * non-blank); PKCS#12 sends pkcs12Base64 (+ password when non-blank). */
export async function toUploadBody(v: UploadValue): Promise<CertificateVersionUpload> {
  if (v.format === 'pem') {
    const body: CertificateVersionUpload = { certificatePem: v.certificatePem };
    if (v.privateKeyPem.trim()) body.privateKeyPem = v.privateKeyPem;
    return body;
  }
  const body: CertificateVersionUpload = { pkcs12Base64: v.file ? await readBase64(v.file) : '' };
  if (v.password) body.password = v.password;
  return body;
}
