import { expect, it } from 'vitest';
import { makeCert } from '@/test/fixtures';
import { canContinueNames, effectiveCaId, fromCertificate, initialWizard, toCertificateInput, wizardReducer as r } from './state';

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

it('setRules marks rulesTouched, keeping whatever per-row methods the rules already carry', () => {
  const rules = [
    { match: 'example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
    { match: 'api.example.com', method: 'http-01' as const, via: 'server' as const },
  ];
  const s = r(initialWizard, { type: 'setRules', rules });
  expect(s.rules).toEqual(rules);
  expect(s.rulesTouched).toBe(true);
});

it('blocks Next on no names, invalid names, or more than 100 names', () => {
  expect(canContinueNames(initialWizard)).toBe(false);
  expect(canContinueNames(r(initialWizard, { type: 'addNames', names: ['bad_x.example.com'] }))).toBe(false);
  const many = Array.from({ length: 101 }, (_, i) => `h${i}.example.com`);
  expect(canContinueNames(r(initialWizard, { type: 'addNames', names: many }))).toBe(false);
  expect(canContinueNames(r(initialWizard, { type: 'addNames', names: many.slice(0, 100) }))).toBe(true);
});

it('fromCertificate round-trips mixed per-rule methods unchanged', () => {
  const rules = [
    { match: 'example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
    { match: 'api.example.com', method: 'http-01' as const, via: 'agent' as const, clientId: 'c-1' },
    { match: 'mail.example.com', method: 'tls-alpn-01' as const, clientId: 'c-2' },
  ];
  const s = fromCertificate(makeCert({ verificationRules: rules }));
  expect(s.rules).toEqual(rules);
});

it('builds the create body with the CN inside sans', () => {
  const s = r(initialWizard, { type: 'addNames', names: ['www.example.com', '*.example.com'] });
  expect(toCertificateInput(s)).toEqual({ name: 'www.example.com', commonName: 'www.example.com', sans: ['www.example.com', '*.example.com'], verificationRules: [], overrides: {} });
});

// Task 4 (R12 deviation): for a private effective CA, rules the user never
// touched are sent as [], not whatever the auto-prefill computed.
it('private untouched rules sent empty', () => {
  let s = r(initialWizard, { type: 'addNames', names: ['www.example.com'] });
  s = r(s, { type: 'prefillRules', rules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }] });
  expect(s.rulesTouched).toBe(false);
  expect(toCertificateInput(s, { privateCa: true }).verificationRules).toEqual([]);
  // Unaffected for an acme (non-private) effective CA.
  expect(toCertificateInput(s, { privateCa: false }).verificationRules).toEqual(s.rules);
});

it('private touched rules kept', () => {
  let s = r(initialWizard, { type: 'addNames', names: ['www.example.com'] });
  s = r(s, { type: 'setRules', rules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }] });
  expect(s.rulesTouched).toBe(true);
  expect(toCertificateInput(s, { privateCa: true }).verificationRules).toEqual(s.rules);
});

it('effectiveCaId prefers a cert override, else the inherited default', () => {
  const inherited = { caId: { value: 'ca-org', source: 'org' as const } };
  expect(effectiveCaId({ overrides: { caId: 'ca-cert' } }, inherited)).toBe('ca-cert');
  expect(effectiveCaId({ overrides: {} }, inherited)).toBe('ca-org');
  expect(effectiveCaId({ overrides: {} }, {})).toBeUndefined();
});
