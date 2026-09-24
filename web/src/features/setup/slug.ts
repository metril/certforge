export const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

// Whitespace and ASCII punctuation (including "-" itself) are word
// separators and collapse to one hyphen; combining marks are stripped so
// accented Latin letters fold to their base letter (ü → u); any other
// character NFKD/lowercasing didn't reduce to a-z0-9 (e.g. "ß", which has no
// NFKD decomposition) is dropped rather than turned into a separator, so
// letters on either side of it join directly.
const SEPARATORS = /[\s!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~]+/g;
const COMBINING_MARKS = /[̀-ͯ]/g;

export function toSlug(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(COMBINING_MARKS, '')
    .replace(SEPARATORS, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/, '');
}
