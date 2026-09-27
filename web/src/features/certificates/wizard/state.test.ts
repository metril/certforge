import { expect, it } from 'vitest';
import { canContinueNames, initialWizard, toCertificateInput, wizardReducer as r } from './state';

it('adds names, dedupes, and makes the first one the CN and default name', () => {
  let s = r(initialWizard, { type: 'addNames', names: ['www.example.com', 'api.example.com'] });
  s = r(s, { type: 'addNames', names: ['api.example.com', '*.example.com'] });
  expect(s.names).toEqual(['www.example.com', 'api.example.com', '*.example.com']);
  expect(s.cn).toBe('www.example.com');
  expect(s.name).toBe('www.example.com');
});

it('moves the CN when it is removed or reassigned, and keeps a typed name', () => {
  let s = r(initialWizard, { type: 'addNames', names: ['a.example.com', 'b.example.com'] });
  s = r(s, { type: 'removeName', name: 'a.example.com' });
  expect(s.cn).toBe('b.example.com');
  s = r(s, { type: 'setName', name: 'Edge' });
  s = r(s, { type: 'addNames', names: ['c.example.com'] });
  s = r(s, { type: 'setCn', name: 'c.example.com' });
  expect(s.cn).toBe('c.example.com');
  expect(s.name).toBe('Edge');
});

it('keeps rules in step with the method', () => {
  let s = r(initialWizard, { type: 'setRules', rules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1', via: 'server' }] });
  s = r(s, { type: 'setMethod', method: 'manual-dns' });
  expect(s.rules).toEqual([{ match: 'example.com', method: 'manual-dns', via: 'server' }]);
  expect(s.rulesTouched).toBe(true);
});

it('blocks Next on no names, invalid names, or more than 100 names', () => {
  expect(canContinueNames(initialWizard)).toBe(false);
  expect(canContinueNames(r(initialWizard, { type: 'addNames', names: ['bad_x.example.com'] }))).toBe(false);
  const many = Array.from({ length: 101 }, (_, i) => `h${i}.example.com`);
  expect(canContinueNames(r(initialWizard, { type: 'addNames', names: many }))).toBe(false);
  expect(canContinueNames(r(initialWizard, { type: 'addNames', names: many.slice(0, 100) }))).toBe(true);
});

it('builds the create body with the CN inside sans', () => {
  const s = r(initialWizard, { type: 'addNames', names: ['www.example.com', '*.example.com'] });
  expect(toCertificateInput(s)).toEqual({ name: 'www.example.com', commonName: 'www.example.com', sans: ['www.example.com', '*.example.com'], verificationRules: [], overrides: {} });
});
