import type { OutputFile, OutputPart } from '@/api/types';

export const OUTPUT_PARTS: OutputPart[] = ['cert', 'chain', 'fullchain', 'key', 'combined'];
export type FileErrors = Partial<Record<'path' | 'parts' | 'mode' | 'owner' | 'group', string>>;

const MODE = /^0?[0-7]{3}$/;
const ACCOUNT = /^[A-Za-z0-9._-]{0,32}$/;
const ACCOUNT_MSG = 'Letters, digits, dot, dash or underscore.';

export function emptyFile(): OutputFile {
  return { path: '', format: 'pem', parts: ['fullchain'], owner: '', group: '', mode: '0640' };
}

/** Mirrors the server's delivery.CleanPath (plan 3A Task 6), so a bad path
 * never reaches the API. */
export function pathError(p: string): string | null {
  if (!p) return 'Enter a path.';
  if (!p.startsWith('/')) return 'Use an absolute path.';
  if (p.endsWith('/')) return 'Name a file, not a directory.';
  if (p.slice(1).split('/').some((s) => s === '' || s === '.' || s === '..')) return 'Remove empty, . and .. segments.';
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
    if (!MODE.test(f.mode)) e.mode = 'Use octal, such as 0640.';
    if (!ACCOUNT.test(f.owner)) e.owner = ACCOUNT_MSG;
    if (!ACCOUNT.test(f.group)) e.group = ACCOUNT_MSG;
    return e;
  });
}

export const hasErrors = (errs: FileErrors[]) => errs.some((e) => Object.keys(e).length > 0);

/** Key material with the "other" read bit set. */
export function keyReadableByOthers(f: OutputFile): boolean {
  if (!MODE.test(f.mode) || !f.parts.some((p) => p === 'key' || p === 'combined')) return false;
  return (parseInt(f.mode, 8) & 0o004) !== 0;
}
