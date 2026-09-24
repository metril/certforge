import { describe, expect, it } from 'vitest';
import { fieldFromTitle, fromDefault, fromEffective, ISSUANCE_FIELDS } from './issuanceFields';

const ctx = { cas: [], accounts: [], credentials: [] };
const renewPolicy = ISSUANCE_FIELDS.find((f) => f.key === 'renewPolicy')!;

describe('renewPolicy copy (preflight A9: value is percent of lifetime REMAINING)', () => {
  it('shows the percent copy as "remains", not "elapsed"', () => {
    expect(renewPolicy.display({ mode: 'percent', value: 33, useAri: false }, ctx)).toBe('When 33% of the lifetime remains');
  });
  it('shows the days copy', () => {
    expect(renewPolicy.display({ mode: 'days', value: 30, useAri: false }, ctx)).toBe('30 days before expiry');
  });
  it('appends ARI when on', () => {
    expect(renewPolicy.display({ mode: 'percent', value: 33, useAri: true }, ctx)).toBe('When 33% of the lifetime remains, ARI on');
  });
  it('defaults to the built-in policy (BuiltinDefaults(): percent, 33)', () => {
    expect(renewPolicy.initial(ctx)).toEqual({ mode: 'percent', value: 33, useAri: false });
  });
});

describe('fromDefault / fromEffective', () => {
  it('fromDefault is always source default with a null value', () => {
    expect(fromDefault()).toEqual({ value: null, source: 'default' });
  });
  it('fromEffective looks up the field and falls back to default when absent', () => {
    const eff = { keyType: { value: 'rsa2048', source: 'org' } } as never;
    expect(fromEffective(eff)('keyType')).toEqual({ value: 'rsa2048', source: 'org' });
    expect(fromEffective(eff)('caId')).toEqual({ value: null, source: 'default' });
  });
});

describe('fieldFromTitle (a 422 title is always "Invalid <field>")', () => {
  it.each([
    ['Invalid caId', 'caId'],
    ['Invalid accountId', 'accountId'],
    ['Invalid renewPolicy.value', 'renewPolicy'],
    ['Invalid renewPolicy.mode', 'renewPolicy'],
    ['Invalid propagationSeconds', 'propagationSeconds'],
    ['Invalid verificationRules', null],
    ['Something else', null],
  ])('%s -> %s', (title, field) => {
    expect(fieldFromTitle(title)).toBe(field);
  });
});
