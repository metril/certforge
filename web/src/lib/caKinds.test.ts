import { expect, it } from 'vitest';
import { ca as caAcme, caLocal, caVaultPki, iso, NOW } from '@/test/fixtures';
import { caTone, crlUrlFor, isPrivate, KIND_LABEL, kindOf } from './caKinds';

it('labels', () => {
  expect(KIND_LABEL).toEqual({ acme: 'ACME', localca: 'Built-in CA', vaultpki: 'Vault PKI' });
});

it('isPrivate', () => {
  expect(isPrivate(caAcme)).toBe(false);
  expect(isPrivate(caLocal)).toBe(true);
  expect(isPrivate(caVaultPki)).toBe(true);
  expect(kindOf(undefined)).toBe('acme');
  expect(kindOf(caVaultPki)).toBe('vaultpki');
});

it('crlUrlFor undefined without crlUrl', () => {
  expect(crlUrlFor(caVaultPki)).toBeUndefined();
  expect(crlUrlFor(caLocal)).toBe(caLocal.crlUrl);
});

it('caTone thresholds', () => {
  expect(caTone(iso(60), NOW)).toBe('valid');
  expect(caTone(iso(10), NOW)).toBe('expiring');
  expect(caTone(iso(-1), NOW)).toBe('expired');
  expect(caTone(undefined, NOW)).toBe('neutral');
});
