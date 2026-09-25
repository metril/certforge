/** The last path segment of `value` (after any `/` or `\`), so a header that
 * smuggles a directory (deliberately, like `../x.pem`, or incidentally)
 * never becomes part of the saved filename. */
function basename(value: string): string {
  const segments = value.split(/[/\\]+/).filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1]! : value;
}

/** Reads a filename from a Content-Disposition header, preferring the RFC
 * 5987 `filename*` (percent-encoded, UTF-8) form over the plain `filename`
 * one (quoted or not); falls back to `fallback` when neither is present.
 * Fix round 1 (review, Take now #4): a malformed percent-encoding in
 * `filename*` (decodeURIComponent throws) falls back to the raw captured
 * value rather than losing the filename entirely. */
export function filenameFrom(res: Response, fallback: string): string {
  const cd = res.headers.get('Content-Disposition') ?? '';
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (star) {
    const raw = star[1]!;
    try {
      return basename(decodeURIComponent(raw));
    } catch {
      return basename(raw);
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(cd);
  return plain ? basename(plain[1]!) : fallback;
}

/** Triggers a browser save of `blob` as `filename` via a throwaway anchor. */
export function saveBlob(blob: Blob, filename: string): void {
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(href), 1_000);
}
