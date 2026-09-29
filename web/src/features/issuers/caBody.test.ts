import { expect, it } from 'vitest';
import { UNCHANGED } from '@/api/types';
import { caLocal, presets } from '@/test/fixtures';
import { emptyAcme, emptyLocalCa, emptyVaultPki, initialDraft, toCaInput, type CaDraft } from './caBody';

it('acme body unchanged', () => {
  const draft: CaDraft = {
    kind: 'acme',
    name: 'ZeroSSL prod',
    acme: { preset: 'zerossl', directoryUrl: presets[2]!.directoryUrl, trustBundlePem: '', eabKid: 'kid-1', eabHmac: 'secret-hmac', resolvers: [] },
    localca: emptyLocalCa,
    vaultpki: emptyVaultPki,
  };
  expect(toCaInput(draft, { presets })).toEqual({
    name: 'ZeroSSL prod',
    type: 'acme',
    preset: 'zerossl',
    directoryUrl: presets[2]!.directoryUrl,
    trustBundlePem: undefined,
    eabKid: 'kid-1',
    eabHmac: 'secret-hmac',
    resolvers: [],
  });
});

it('acme body drops eab fields for a preset that does not use it', () => {
  const draft: CaDraft = {
    kind: 'acme',
    name: "Let's Encrypt",
    acme: { preset: 'letsencrypt', directoryUrl: presets[0]!.directoryUrl, trustBundlePem: '', eabKid: '', eabHmac: undefined, resolvers: [] },
    localca: emptyLocalCa,
    vaultpki: emptyVaultPki,
  };
  const body = toCaInput(draft, { presets });
  expect(body.eabKid).toBeUndefined();
  expect(body.eabHmac).toBeUndefined();
});

it('localca generate body', () => {
  const draft: CaDraft = {
    kind: 'localca',
    name: 'Internal CA',
    acme: emptyAcme,
    localca: {
      importing: false,
      config: {
        subject: { commonName: 'Internal CA' },
        keyType: 'ec384',
        rootValidityYears: 10,
        issuingValidityYears: 3,
        maxLeafDays: 397,
        crl: true,
        importPem: 'stale-pem',
        importKeyPem: 'stale-key',
      },
    },
    vaultpki: emptyVaultPki,
  };
  expect(toCaInput(draft, { presets })).toEqual({
    name: 'Internal CA',
    type: 'localca',
    config: {
      subject: { commonName: 'Internal CA' },
      keyType: 'ec384',
      rootValidityYears: 10,
      issuingValidityYears: 3,
      maxLeafDays: 397,
      crl: true,
    },
  });
});

it('localca import drops generated fields', () => {
  const draft: CaDraft = {
    kind: 'localca',
    name: 'Imported CA',
    acme: emptyAcme,
    localca: {
      importing: true,
      config: {
        subject: { commonName: 'stale' },
        keyType: 'ec256',
        rootValidityYears: 10,
        issuingValidityYears: 3,
        maxLeafDays: 397,
        crl: true,
        importPem: '-----BEGIN CERTIFICATE-----',
        importKeyPem: '-----BEGIN PRIVATE KEY-----',
      },
    },
    vaultpki: emptyVaultPki,
  };
  expect(toCaInput(draft, { presets })).toEqual({
    name: 'Imported CA',
    type: 'localca',
    config: { maxLeafDays: 397, crl: true, importPem: '-----BEGIN CERTIFICATE-----', importKeyPem: '-----BEGIN PRIVATE KEY-----' },
  });
});

it('edit sends only mutable config', () => {
  const draft = initialDraft(caLocal, 'localca');
  draft.localca.config = { ...draft.localca.config, maxLeafDays: 200, crl: false };
  const body = toCaInput(draft, { presets, ca: caLocal });
  expect(body).toEqual({ name: caLocal.name, type: 'localca', config: { maxLeafDays: 200, crl: false } });
});

it('vaultpki sends every field, create and edit alike', () => {
  const draft: CaDraft = { kind: 'vaultpki', name: 'Vault PKI', acme: emptyAcme, localca: emptyLocalCa, vaultpki: { config: { mount: 'pki', role: 'certforge', ttl: '2160h' } } };
  expect(toCaInput(draft, { presets })).toEqual({ name: 'Vault PKI', type: 'vaultpki', config: { mount: 'pki', role: 'certforge', ttl: '2160h' } });
});

it('initialDraft seeds the stored EAB sentinel for an acme CA', () => {
  const withEab = { ...caLocal, type: 'acme' as const, hasEab: true, eabKid: 'kid-1', preset: 'zerossl' as const };
  const draft = initialDraft(withEab, 'acme');
  expect(draft.acme.eabHmac).toBe(UNCHANGED);
});
