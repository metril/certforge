import { expect, it } from 'vitest';
import { fieldFromDetail } from './CaSheet';

it('maps whole-word name to the Name field only', () => {
  expect(fieldFromDetail('name is required')).toBe('name');
  expect(fieldFromDetail('CA name already exists')).toBe('name');
  expect(fieldFromDetail('hostname is invalid')).toBeNull();
  expect(fieldFromDetail('invalid DNS name')).toBeNull();
  expect(fieldFromDetail('directory url unreachable')).toBe('directoryUrl');
});
