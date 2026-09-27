// Characters that are easy to mis-type or mis-read are excluded: 0/O, 1/l/I.
const EXCLUDED = new Set(['0', 'O', '1', 'l', 'I']);

function buildAlphabet(): string {
  const chars: string[] = [];
  for (let c = 65; c <= 90; c++) chars.push(String.fromCharCode(c)); // A-Z
  for (let c = 97; c <= 122; c++) chars.push(String.fromCharCode(c)); // a-z
  for (let c = 48; c <= 57; c++) chars.push(String.fromCharCode(c)); // 0-9
  return chars.filter((c) => !EXCLUDED.has(c)).join('');
}

const ALPHABET = buildAlphabet();

/** A random password for export/layout use, drawn from an unambiguous
 * alphabet (A-Z, a-z, 0-9 minus 0 O 1 l I) with rejection sampling so every
 * character is equally likely. */
export function generatePassword(len = 24): string {
  const n = ALPHABET.length;
  const max = 256 - (256 % n);
  const out: string[] = [];
  const byte = new Uint8Array(1);
  while (out.length < len) {
    crypto.getRandomValues(byte);
    const v = byte[0]!;
    if (v >= max) continue;
    out.push(ALPHABET[v % n]!);
  }
  return out.join('');
}
