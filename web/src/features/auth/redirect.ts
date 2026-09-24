/** Only same-origin app paths; never back into login or setup. */
export function safeRedirect(r: string | undefined): string {
  if (!r || !r.startsWith('/') || r.startsWith('//') || r.startsWith('/\\')) return '/';
  if (r.startsWith('/login') || r.startsWith('/setup')) return '/';
  return r;
}
