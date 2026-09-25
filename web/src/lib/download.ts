/** Reads a filename from a Content-Disposition header, preferring the RFC
 * 5987 `filename*` (percent-encoded, UTF-8) form over the plain `filename`
 * one; falls back to `fallback` when neither is present. */
export function filenameFrom(res: Response, fallback: string): string {
  const cd = res.headers.get('Content-Disposition') ?? '';
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (star) return decodeURIComponent(star[1]!);
  const plain = /filename="?([^";]+)"?/i.exec(cd);
  return plain ? plain[1]! : fallback;
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
