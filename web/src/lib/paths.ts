/** Mirrors the server's delivery.CleanPath (plan 3A Task 6), so a bad path
 * never reaches the API. Used for both a layout file's `path` and (Task 3)
 * an http-01-via-agent rule's `webroot`. */
export function pathError(p: string): string | null {
  if (!p) return 'Enter a path.';
  if (p.includes('\0')) return 'Remove the embedded NUL character.';
  if (!p.startsWith('/')) return 'Use an absolute path.';
  if (p === '/' || p.endsWith('/')) return 'Name a file, not a directory.';
  if (p.slice(1).split('/').some((s) => s === '' || s === '.' || s === '..')) return 'Remove empty, . and .. segments.';
  return null;
}
