import { describe, expect, it } from 'vitest';
import { fieldOfTitle } from './errors';

describe('fieldOfTitle (a 422 title is always "Invalid <field>" or "Invalid <field>.<sub>")', () => {
  it.each([
    ['Invalid password', 'password'],
    ['Invalid alias', 'alias'],
    ['Invalid overrides.renewPolicy', 'overrides'],
    [undefined, null],
    ['', null],
    ['Something else entirely', 'Something else entirely'],
  ])('%s -> %s', (title, field) => {
    expect(fieldOfTitle(title)).toBe(field);
  });
});
