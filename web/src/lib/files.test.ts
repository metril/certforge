import { expect, it } from 'vitest';
import { fmtBytes, readBase64 } from './files';

it('readBase64 round-trips bytes', async () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255, 65, 66, 67]);
  const file = new File([bytes], 'x.bin', { type: 'application/octet-stream' });
  const b64 = await readBase64(file);
  const decoded = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  expect(decoded).toEqual(bytes);
});

it('fmtBytes(33554432) is "32 MiB"', () => {
  expect(fmtBytes(33_554_432)).toBe('32 MiB');
});
