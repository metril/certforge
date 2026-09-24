import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fieldFromTitle, fromBuiltin, fromDefault, fromEffective, fullPayload, ISSUANCE_FIELDS } from './issuanceFields';

const ctx = { cas: [], accounts: [], credentials: [] };
const renewPolicy = ISSUANCE_FIELDS.find((f) => f.key === 'renewPolicy')!;
const caField = ISSUANCE_FIELDS.find((f) => f.key === 'caId')!;
const accountField = ISSUANCE_FIELDS.find((f) => f.key === 'accountId')!;

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

describe('fromBuiltin (review fix round 1, #1)', () => {
  it('is always source default, with the built-in value for display', () => {
    expect(fromBuiltin({ keyType: 'ec256' })('keyType')).toEqual({ value: 'ec256', source: 'default' });
  });
  it('falls back to null when the built-in value itself is absent', () => {
    expect(fromBuiltin({})('caId')).toEqual({ value: null, source: 'default' });
  });
});

describe('fullPayload (review fix round 1, #1/#3)', () => {
  it('sends every field explicitly: the given value, or null for one that is absent', () => {
    expect(fullPayload({ keyType: 'rsa2048' })).toEqual({
      caId: null,
      accountId: null,
      keyType: 'rsa2048',
      renewPolicy: null,
      preferredChain: null,
      reuseKey: null,
      mustStaple: null,
      propagationSeconds: null,
      resolvers: null,
    });
  });
});

describe('lookup fields disable Override when there is nothing to choose (review fix round 1, #4)', () => {
  it('caId', () => {
    expect(caField.disabledReason?.({ cas: [], accounts: [], credentials: [] })).toBe('No CAs yet');
    expect(caField.disabledReason?.({ cas: [{ id: 'ca-1', name: 'x', preset: 'letsencrypt', directoryUrl: '', resolvers: [] }], accounts: [], credentials: [] })).toBeUndefined();
  });
  it('accountId', () => {
    expect(accountField.disabledReason?.({ cas: [], accounts: [], credentials: [] })).toBe('No accounts yet');
  });
});

describe('editor widths (review fix round 1, #8: no fixed width that overflows a 375px viewport)', () => {
  it('never uses a bare w-72/w-96 class — every editor wrapper is w-full max-w-96', () => {
    const src = readFileSync(resolve(import.meta.dirname, './issuanceFields.tsx'), 'utf8');
    expect(src).not.toMatch(/className="w-72/);
    expect(src).not.toMatch(/className="w-96/);
  });
});
