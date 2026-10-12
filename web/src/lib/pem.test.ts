import { readFileSync } from 'node:fs';
import path from 'node:path';
import { expect, it } from 'vitest';
import { appendPem, cnOfDn, derToPem, fileBytesToPem, parseCert, summarizeBundle } from './pem';

const fixtures = path.resolve(import.meta.dirname, '../../e2e/fixtures');
const PEM = readFileSync(path.join(fixtures, 'ca.pem'), 'utf8');
const DER = new Uint8Array(readFileSync(path.join(fixtures, 'ca.der')));

it('converts DER to PEM wrapped at 64 columns', () => {
  expect(derToPem(DER)).toBe(PEM);
  expect(fileBytesToPem(DER)).toBe(PEM);
  expect(fileBytesToPem(new TextEncoder().encode('nope'))).toBeNull();
});

it('reads the common name and a GeneralizedTime expiry', () => {
  expect(parseCert(DER)).toEqual({ cn: 'CertForge Test Root', notAfter: new Date('2126-09-18T05:40:53Z') });
  expect(parseCert(DER.subarray(0, 40))).toBeNull();
});

it('summarizes a bundle and flags what is not certificates', () => {
  expect(summarizeBundle(PEM + PEM).certs).toHaveLength(2);
  expect(summarizeBundle('').problem).toBeUndefined();
  expect(summarizeBundle('hello').problem).toMatch(/^Not PEM/);
  expect(summarizeBundle(`${PEM}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`).problem).toMatch(/private key/);
  expect(summarizeBundle(`junk\n${PEM}`).problem).toMatch(/outside/);
});

it('appends only certificates not already present', () => {
  expect(appendPem('', PEM)).toBe(PEM);
  expect(appendPem(PEM, PEM)).toBe(PEM);
  expect(appendPem(PEM.trim(), '-----BEGIN CERTIFICATE-----\nAB\n-----END CERTIFICATE-----')).toBe(`${PEM}-----BEGIN CERTIFICATE-----\nAB\n-----END CERTIFICATE-----\n`);
});

it('takes the CN from a distinguished name', () => {
  expect(cnOfDn('CN=a\\, b,O=x')).toBe('a, b');
  expect(cnOfDn('O=x,CN=y')).toBe('y');
  expect(cnOfDn('O=x')).toBe('O=x');
});
