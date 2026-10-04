import { expect, test } from 'vitest';
import { failedWithoutData } from './queryState';

test('failedWithoutData is true only for an error with no data', () => {
  expect(failedWithoutData({ isError: true, data: undefined })).toBe(true);
  expect(failedWithoutData({ isError: true, data: [] })).toBe(false);
  expect(failedWithoutData({ isError: true, data: [1] })).toBe(false);
  expect(failedWithoutData({ isError: false, data: undefined })).toBe(false);
});
