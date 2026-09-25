import { expect, it } from 'vitest';
import { filenameFrom } from './download';

it.each([
  ['attachment; filename="www.zip"', 'www.zip'],
  ["attachment; filename*=UTF-8''caf%C3%A9.pem", 'café.pem'],
  ['', 'fallback.pem'],
])('filenameFrom(%s) = %s', (cd, expected) => {
  expect(filenameFrom(new Response('', { headers: cd ? { 'Content-Disposition': cd } : {} }), 'fallback.pem')).toBe(expected);
});
