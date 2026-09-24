/**
 * Normalizes a zone typed into the DNS credential test dialog: strips a
 * pasted URL's scheme and path (`https://example.com/` -> `example.com`),
 * lowercases it, and rejects anything with whitespace or an empty label
 * (a leading/trailing/doubled dot). Returns null for invalid input.
 */
export function normalizeZone(input: string): string | null {
  let z = input.trim();
  if (!z) return null;
  z = z.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  z = (z.split(/[/?#]/)[0] ?? '').toLowerCase();
  if (!z || /\s/.test(z)) return null;
  if (z.split('.').some((label) => label === '')) return null;
  return z;
}
