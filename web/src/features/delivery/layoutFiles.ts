import type { OutputFile, OutputPart } from '@/api/types';
import { pathError } from '@/lib/paths';

export const OUTPUT_PARTS: OutputPart[] = ['cert', 'chain', 'fullchain', 'key', 'combined'];
export type FileErrors = Partial<Record<'path' | 'parts' | 'mode' | 'owner' | 'group', string>>;

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
    if (f.parts.length === 0) e.parts = 'Pick at least one part.';
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

/** Key material with the "other" read bit set. */
export function keyReadableByOthers(f: OutputFile): boolean {
  if (!MODE.test(f.mode) || !f.parts.some((p) => p === 'key' || p === 'combined')) return false;
  return (parseInt(f.mode, 8) & 0o004) !== 0;
}
