// Client-side PEM helpers for the CA bundle input: enough to split a bundle,
// convert a DER upload, and show each certificate's common name and expiry.
// The server's own pem-bundle check stays the authority (it 422s bad input).

export type PemBlock = { type: string; b64: string };
export type CertSummary = { cn: string; notAfter: Date | null };
export type BundleSummary = { certs: CertSummary[]; problem?: string };

const BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

export function splitPem(text: string): { blocks: PemBlock[]; stray: boolean } {
  const blocks: PemBlock[] = [];
  for (const m of text.matchAll(BLOCK)) blocks.push({ type: m[1]!, b64: m[2]!.replace(/\s+/g, '') });
  const stray = text.replace(BLOCK, '').trim() !== '';
  return { blocks, stray };
}

export function b64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function blockToPem(type: string, b64: string): string {
  return `-----BEGIN ${type}-----\n${b64.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END ${type}-----\n`;
}

/** DER bytes to a PEM CERTIFICATE block, base64 wrapped at 64 columns. */
export function derToPem(der: Uint8Array): string {
  return blockToPem('CERTIFICATE', bytesToB64(der));
}

/** Reads an uploaded file as PEM text: PEM is kept as-is, DER is converted.
 * Returns null when the file is neither. */
export function fileBytesToPem(bytes: Uint8Array): string | null {
  const text = new TextDecoder().decode(bytes);
  if (text.includes('-----BEGIN ')) return text;
  if (bytes[0] === 0x30 && parseCert(bytes)) return derToPem(bytes);
  return null;
}

/** Appends the certificates in `add` that `current` doesn't already hold. */
export function appendPem(current: string, add: string): string {
  const have = new Set(splitPem(current).blocks.map((b) => b.b64));
  const fresh = splitPem(add).blocks.filter((b) => {
    if (have.has(b.b64)) return false;
    have.add(b.b64);
    return true;
  });
  if (fresh.length === 0) return current;
  const head = current.trim() === '' ? '' : current.replace(/\s*$/, '\n');
  return head + fresh.map((b) => blockToPem(b.type, b.b64)).join('');
}

// --- minimal DER reader -----------------------------------------------------

type Tlv = { tag: number; start: number; end: number };

function tlv(buf: Uint8Array, off: number): Tlv | null {
  if (off + 2 > buf.length) return null;
  const tag = buf[off]!;
  let len = buf[off + 1]!;
  let start = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i]!;
    start += n;
  }
  const end = start + len;
  return end > buf.length ? null : { tag, start, end };
}

function children(buf: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let off = t.start; off < t.end; ) {
    const c = tlv(buf, off);
    if (!c) return [];
    out.push(c);
    off = c.end;
  }
  return out;
}

function asciiOf(buf: Uint8Array, t: Tlv): string {
  return new TextDecoder().decode(buf.subarray(t.start, t.end));
}

function timeOf(buf: Uint8Array, t: Tlv): Date | null {
  const s = asciiOf(buf, t);
  const m = (t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/ : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/).exec(s);
  if (!m) return null;
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)));
}

const CN = '2.5.4.3';
const O = '2.5.4.10';

function oidOf(buf: Uint8Array, t: Tlv): string {
  const b = buf.subarray(t.start, t.end);
  if (b.length === 0) return '';
  const parts = [Math.floor(b[0]! / 40), b[0]! % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i]! & 0x7f);
    if (!(b[i]! & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

function nameAttrs(buf: Uint8Array, name: Tlv): Map<string, string> {
  const out = new Map<string, string>();
  for (const set of children(buf, name)) {
    for (const atv of children(buf, set)) {
      const [oid, val] = children(buf, atv);
      if (oid?.tag === 0x06 && val && !out.has(oidOf(buf, oid))) out.set(oidOf(buf, oid), asciiOf(buf, val));
    }
  }
  return out;
}

/** Subject common name (or organization) and expiry of a DER certificate;
 * null when the bytes aren't an X.509 certificate. */
export function parseCert(der: Uint8Array): CertSummary | null {
  const cert = tlv(der, 0);
  if (!cert || cert.tag !== 0x30 || cert.end !== der.length) return null;
  const tbs = children(der, cert)[0];
  if (!tbs || tbs.tag !== 0x30) return null;
  let f = children(der, tbs);
  if (f[0]?.tag === 0xa0) f = f.slice(1);
  const [serial, , , validity, subject] = f;
  if (serial?.tag !== 0x02 || validity?.tag !== 0x30 || subject?.tag !== 0x30) return null;
  const times = children(der, validity);
  const attrs = nameAttrs(der, subject);
  return { cn: attrs.get(CN) ?? attrs.get(O) ?? 'No common name', notAfter: times[1] ? timeOf(der, times[1]) : null };
}

/** What a bundle holds, and a client-side note when it isn't plain PEM certificates. */
export function summarizeBundle(text: string): BundleSummary {
  if (text.trim() === '') return { certs: [] };
  const { blocks, stray } = splitPem(text);
  const certs: CertSummary[] = [];
  let bad = 0;
  for (const b of blocks) {
    const der = b.type === 'CERTIFICATE' ? b64ToBytes(b.b64) : null;
    const c = der && parseCert(der);
    if (c) certs.push(c);
    else bad++;
  }
  if (blocks.some((b) => b.type.includes('PRIVATE KEY'))) return { certs, problem: 'Holds a private key. Paste certificates only.' };
  if (blocks.length === 0) return { certs, problem: 'Not PEM. Paste blocks starting with -----BEGIN CERTIFICATE-----.' };
  if (bad > 0) return { certs, problem: `${bad} block${bad === 1 ? ' is' : 's are'} not a readable certificate.` };
  if (stray) return { certs, problem: 'Has text outside the certificate blocks.' };
  return { certs };
}

/** "CN=foo,O=bar" → "foo" (falls back to the whole name). */
export function cnOfDn(dn: string): string {
  return /(?:^|,)\s*CN=((?:\\,|[^,])+)/.exec(dn)?.[1]?.replace(/\\,/g, ',') ?? dn;
}

/** Advisory client check for an SSH private key; the server stays the authority. */
export function privateKeyProblem(text: string): string | null {
  if (text.length > 8192) return 'Private key is longer than 8192 characters.';
  if (/ENCRYPTED PRIVATE KEY/.test(text)) return 'Encrypted PKCS#8 keys are not supported; convert with ssh-keygen -p.';
  if (!/-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----/.test(text)) return 'Not a PEM private key.';
  return null;
}

/** The OpenSSH cipher name (e.g. "none", "aes256-ctr"), or null when `text` isn't an OpenSSH key. */
function opensshCipher(text: string): string | null {
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(text);
  if (!m) return null;
  const bytes = b64ToBytes(m[1]!.replace(/\s+/g, '').slice(0, 96));
  const magic = 'openssh-key-v1\0';
  if (!bytes || bytes.length < magic.length + 4) return null;
  for (let i = 0; i < magic.length; i++) if (bytes[i] !== magic.charCodeAt(i)) return null;
  const o = magic.length;
  const len = ((bytes[o]! << 24) | (bytes[o + 1]! << 16) | (bytes[o + 2]! << 8) | bytes[o + 3]!) >>> 0;
  if (o + 4 + len > bytes.length) return null;
  return new TextDecoder().decode(bytes.subarray(o + 4, o + 4 + len));
}

/** A non-blocking note when the key is passphrase-protected. */
export function privateKeyNote(text: string): string | null {
  const enc = /Proc-Type:\s*4,ENCRYPTED/.test(text) || (opensshCipher(text) ?? 'none') !== 'none';
  return enc ? 'This key is passphrase-protected; enter its passphrase below.' : null;
}
