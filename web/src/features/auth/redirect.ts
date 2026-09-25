function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Only same-origin app paths; never back into login or setup. Mirrors the
 * server's safeNext (internal/api/oidc.go ~23-42): reject anything over
 * 2048 characters, without a leading "/", starting "//" or "/\" (before or
 * after percent-decoding the path), containing a backslash anywhere, or
 * containing any control character (tab, CR, LF, or otherwise).
 */
export function safeRedirect(r: string | undefined): string {
  if (
    !r ||
    r.length > 2048 ||
    !r.startsWith('/') ||
    r.startsWith('//') ||
    r.startsWith('/\\') ||
    r.includes('\\') ||
    hasControlChar(r)
  ) {
    return '/';
  }
  let pathname: string;
  try {
    pathname = decodeURIComponent(new URL(r, 'http://same-origin.invalid').pathname);
  } catch {
    return '/';
  }
  if (pathname.startsWith('//') || pathname.startsWith('/\\')) return '/';
  if (r.startsWith('/login') || r.startsWith('/setup')) return '/';
  return r;
}
