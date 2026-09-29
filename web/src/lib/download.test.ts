import { expect, it } from 'vitest';
import { filenameFrom, safeName } from './download';

it.each([
  ['attachment; filename="www.zip"', 'www.zip'],
  ["attachment; filename*=UTF-8''caf%C3%A9.pem", 'café.pem'],
  ['', 'fallback.pem'],
  // Fix round 1 (review, Take now #4): unquoted filename, a smuggled
  // directory segment (real or path-traversal), and a malformed
  // percent-encoding that must fall back to the raw value, not the fallback name.
  ['attachment; filename=plain.pem', 'plain.pem'],
  ['attachment; filename="../x.pem"', 'x.pem'],
  ["attachment; filename*=UTF-8''bad%zzfile.pem", 'bad%zzfile.pem'],
])('filenameFrom(%s) = %s', (cd, expected) => {
  expect(filenameFrom(new Response('', { headers: cd ? { 'Content-Disposition': cd } : {} }), 'fallback.pem')).toBe(expected);
});

it.each([
  ['Internal CA', 'internal-ca'],
  ['  Weird!! Name..', 'weird-name'],
  ['', 'cert'],
  ['---', 'cert'],
  ['a'.repeat(150), 'a'.repeat(100)],
])('safeName(%s) = %s', (input, expected) => {
  expect(safeName(input)).toBe(expected);
});
