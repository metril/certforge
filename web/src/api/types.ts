import type { components } from './schema';

type S = components['schemas'];

export type Me = S['Me'];
export type Org = S['Org'];
export type CA = S['CA'];
export type CAInput = S['CAInput'];
export type CAPreset = S['CAPreset'];
export type AcmeAccount = S['AcmeAccount'];
// Adaptation (preflight A2): the real components use DNS/Manual DNS casing
// (DNSCredential*, ManualDNS*), not DnsCredential*/ManualDns*; the exported
// alias names below stay as the brief has them, only the right-hand side
// changed. DNSCredentialUpdate and DNSCredentialTestResult are added because
// later tasks (PUT and the live test) need them.
export type DnsCredential = S['DNSCredential'];
export type DnsCredentialInput = S['DNSCredentialInput'];
export type DnsCredentialUpdate = S['DNSCredentialUpdate'];
export type DnsCredentialTestResult = S['DNSCredentialTestResult'];
export type ProviderSchema = S['SchemaEntry'];
export type MetaSchemas = S['MetaSchemas'];
export type IssuanceDefaults = S['IssuanceDefaults'];
export type VerificationRule = S['VerificationRule'];
export type Certificate = S['Certificate'];
export type CertificateInput = S['CertificateInput'];
export type CertificateList = S['CertificateList'];
export type CertificateVersion = S['CertificateVersion'];
export type Attempt = S['IssuanceAttempt'];
export type AttemptStep = S['AttemptStep'];
export type ManualDnsRecord = S['ManualDNSRecord'];
export type ManualDnsConfirmResult = S['ManualDNSConfirmResult'];
export type SettingsSection = S['SettingsSection'];

export type CertStatus = Certificate['status'];
export type KeyType = S['KeyType'];
export type VerificationMethod = VerificationRule['method'];
// Adaptation (preflight A4): the API already returns EffectiveIssuanceDefaults
// with a {value, source} shape per field (Source includes 'cert'), so
// EffectiveMap/EffectiveValue below are plain aliases of it — no hand-rolled
// shape or `as` casts. Kept (fix round 1) because Task 10 imports them.
export type Source = S['Source'];
export type EffectiveIssuanceDefaults = S['EffectiveIssuanceDefaults'];
export type EffectiveMap = EffectiveIssuanceDefaults;
export type EffectiveValue = NonNullable<EffectiveIssuanceDefaults[keyof EffectiveIssuanceDefaults]>;

/** Sent in place of a secret to keep the stored value. */
export const UNCHANGED = '__unchanged__';
