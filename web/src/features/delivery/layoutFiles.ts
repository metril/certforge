import { UNCHANGED } from '@/api/types';
import type { OutputFile, OutputFormat, OutputPart } from '@/api/types';
import { pathError } from '@/lib/paths';

export const OUTPUT_PARTS: OutputPart[] = ['cert', 'chain', 'fullchain', 'key', 'combined', 'extra'];
export const OUTPUT_FORMATS: { value: OutputFormat; label: string }[] = [
  { value: 'pem', label: 'PEM' },
  { value: 'der', label: 'DER' },
  { value: 'p12', label: 'PKCS#12' },
  { value: 'jks', label: 'JKS' },
];
export type FileErrors = Partial<Record<'path' | 'parts' | 'mode' | 'owner' | 'group' | 'encoding' | 'alias', string>>;

// Moved to lib/paths.ts (Task 3): lib/rules.ts's webroot field also needs
// it, and forms shouldn't import from features/delivery. Re-exported here
// so this file's own existing callers are unaffected.
export { pathError };

// Mirrors internal/delivery/delivery.go's modeRe/ownerRe/validateMode/
// validateOwner exactly, so a file that would be rejected server-side is
// caught before it is ever sent.
const MODE = /^0?[0-7]{3}$/;
const ACCOUNT = /^([a-z_][a-z0-9_.-]{0,31}|[0-9]{1,10})?$/;
const ACCOUNT_NUMERIC = /^[0-9]{1,10}$/;
const UINT32_MAX = 4294967295;
const ACCOUNT_MSG = 'Use a user/group name, or a numeric id.';

export function emptyFile(): OutputFile {
  return { path: '', format: 'pem', parts: ['fullchain'], owner: '', group: '', mode: '0640' };
}

/** A format's default parts: PEM defaults to fullchain, DER to cert, and
 * p12/jks take none (mirrors internal/delivery's ValidateFiles). */
function defaultPartsFor(format: OutputFormat): OutputPart[] {
  if (format === 'pem') return ['fullchain'];
  if (format === 'der') return ['cert'];
  return [];
}

const PATH_NAME_FOR_FORMAT: Record<OutputFormat, string> = { pem: 'fullchain.pem', der: 'cert.der', p12: 'bundle.p12', jks: 'keystore.jks' };

/** The Path field's placeholder, which follows the file's format. */
export function pathPlaceholder(format: OutputFormat): string {
  return `/etc/ssl/example.com/${PATH_NAME_FOR_FORMAT[format]}`;
}

/** Rebuilds a file for a newly picked format: parts reset to the format's
 * default, and encoding/alias (which only apply to p12/jks respectively)
 * are dropped when they no longer apply. */
export function withFormat(f: OutputFile, format: OutputFormat): OutputFile {
  const next: OutputFile = { ...f, format, parts: defaultPartsFor(format) };
  if (format !== 'p12') delete next.encoding;
  if (format !== 'jks') delete next.alias;
  return next;
}

/** Mirrors delivery.validateMode: octal, and never world-writable — a
 * layout file can hold a private key, and a mode an agent would write as
 * world-writable is always a mistake. */
export function modeError(mode: string): string | null {
  if (!MODE.test(mode)) return 'Use octal, such as 0640.';
  if ((parseInt(mode, 8) & 0o002) !== 0) return 'Must not be world-writable.';
  return null;
}

/** Mirrors delivery.validateOwner: a user/group name, or a numeric id that
 * fits in a uint32 (the range chown accepts). */
export function accountError(s: string): string | null {
  if (!ACCOUNT.test(s)) return ACCOUNT_MSG;
  if (ACCOUNT_NUMERIC.test(s) && Number(s) > UINT32_MAX) return 'Numeric id must fit in 32 bits.';
  return null;
}

export function validateFiles(files: OutputFile[]): FileErrors[] {
  const seen = new Set<string>();
  return files.map((f) => {
    const e: FileErrors = {};
    const path = f.path.trim();
    const pe = pathError(path);
    if (pe) e.path = pe;
    else if (seen.has(path)) e.path = 'Another file already uses this path.';
    seen.add(path);
    if (f.format === 'der') {
      if (f.parts.length !== 1 || (f.parts[0] !== 'cert' && f.parts[0] !== 'key')) e.parts = 'Pick certificate or key.';
    } else if (f.format === 'pem' && f.parts.length === 0) {
      e.parts = 'Pick at least one part.';
    }
    const me = modeError(f.mode);
    if (me) e.mode = me;
    const oe = accountError(f.owner);
    if (oe) e.owner = oe;
    const ge = accountError(f.group);
    if (ge) e.group = ge;
    return e;
  });
}

export const hasErrors = (errs: FileErrors[]) => errs.some((e) => Object.keys(e).length > 0);

/** Whether a file holds key material: PEM key/combined, a DER key file, or
 * any p12/jks file (which always bundles the key). */
function isKeyBearing(f: OutputFile): boolean {
  if (f.format === 'p12' || f.format === 'jks') return true;
  if (f.format === 'der') return f.parts.includes('key');
  return f.parts.some((p) => p === 'key' || p === 'combined');
}

/** Key material with the "other" read bit set. */
export function keyReadableByOthers(f: OutputFile): boolean {
  if (!MODE.test(f.mode) || !isKeyBearing(f)) return false;
  return (parseInt(f.mode, 8) & 0o004) !== 0;
}

export type LayoutErrors = Partial<Record<'password' | 'extraCertificateIds', string>>;

/** Layout-level validation: the password (required, length-checked) when
 * any file needs one, and the extra-certificates cap. Mirrors
 * internal/api/delivery.go's checkLayoutPassword/parseLayoutInput, with the
 * UI's own shorter wording. */
export function layoutErrors({
  files,
  password,
  passwordSet,
  extraCertificateIds,
}: {
  files: OutputFile[];
  password: string | undefined;
  passwordSet: boolean;
  extraCertificateIds: string[];
}): LayoutErrors {
  const e: LayoutErrors = {};
  const needsPassword = files.some((f) => f.format === 'p12' || f.format === 'jks');
  const needsJKS = files.some((f) => f.format === 'jks');
  if (needsPassword) {
    const keepsStored = password === UNCHANGED && passwordSet;
    const provided = password !== undefined && password !== '' && password !== UNCHANGED;
    if (!keepsStored && !provided) {
      e.password = 'Enter a password.';
    } else if (provided) {
      const len = [...password!].length;
      if (needsJKS && len < 6) e.password = 'At least 6 characters.';
      else if (len > 128) e.password = 'At most 128 characters.';
    }
  }
  if (extraCertificateIds.length > 10) e.extraCertificateIds = 'Up to 10.';
  return e;
}
