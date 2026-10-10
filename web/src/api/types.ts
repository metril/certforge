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
export type CertBrief = S['CertificateBrief'];
export type CertificateOverview = S['CertificateOverview'];
export type CertificateVersion = S['CertificateVersion'];
export type Attempt = S['IssuanceAttempt'];
export type AttemptStep = S['AttemptStep'];
export type ManualDnsRecord = S['ManualDNSRecord'];
export type ManualDnsConfirmResult = S['ManualDNSConfirmResult'];
export type SettingsSection = S['SettingsSection'];

// Phase 4B Task 1: exports, uploads, imports and the rate ledger.
export type ExportRequest = S['ExportRequest'];
export type ExportFormat = S['ExportFormat'];
export type P12Encoding = S['P12Encoding'];
export type CertificateUpload = S['CertificateUpload'];
export type CertificateVersionUpload = S['CertificateVersionUpload'];
export type ImportResult = S['ImportResult'];
export type ImportItem = S['ImportItem'];
export type ImportSource = S['ImportSource'];
export type ImportAction = S['ImportAction'];
export type RateLedger = S['RateLedger'];
export type RateLedgerItem = S['RateLedgerItem'];
export type RateLimits = S['RateLimits'];
export type RateLimitName = S['RateLimitName'];
export type AriWindow = S['AriWindow'];
export type ChallengeVia = S['ChallengeVia'];

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

export type AuthMethods = S['AuthMethods'];
export type MeBinding = S['MeBinding'];
export type Role = S['Role'];
export type UserDetail = S['UserDetail'];
export type RoleBinding = S['RoleBinding'];
export type RoleBindingInput = S['RoleBindingInput'];
export type SubjectType = S['SubjectType'];
export type ApiKey = S['ApiKey'];
export type ApiKeyInput = S['ApiKeyInput'];
export type ApiKeyCreated = S['ApiKeyCreated'];
export type ApiKeyScope = S['ApiKeyScope'];
export type Site = S['Site'];
export type AuditEvent = S['AuditEvent'];
export type AuditEventList = S['AuditEventList'];
export type AuditChainStatus = S['AuditChainStatus'];
export type AuthenticationTestResult = S['AuthenticationTestResult'];

export type Client = S['Client'];
export type ClientInput = S['ClientInput'];
export type ClientUpdate = S['ClientUpdate'];
export type ClientCreated = S['ClientCreated'];
export type ClientStatus = S['ClientStatus'];
export type EnrollmentRequest = S['EnrollmentRequest'];
export type Grant = S['Grant'];
export type GrantInput = S['GrantInput'];
export type GrantUpdate = S['GrantUpdate'];
export type GrantDelivery = S['GrantDelivery'];
export type Deployment = S['Deployment'];
export type DeploymentState = S['DeploymentState'];
export type FileDigest = S['FileDigest'];
export type CertificateDeployment = S['CertificateDeployment'];
export type HookRun = S['HookRun'];
export type Layout = S['Layout'];
export type LayoutInput = S['LayoutInput'];
export type OutputFile = S['OutputFile'];
export type OutputFormat = S['OutputFormat'];
export type OutputPart = S['OutputPart'];
export type DeployTarget = S['DeployTarget'];
export type DeployTargetInput = S['DeployTargetInput'];
export type Hook = S['Hook'];
export type HookInput = S['HookInput'];
export type HookPhase = S['HookPhase'];
export type AgentCA = S['AgentCA'];
export type AgentCAList = S['AgentCAList'];
export type AgentListener = S['AgentListener'];

// Phase 5B Task 1: private CAs, Vault settings and server grants.
export type CaType = S['CaType'];
export type LocalCaConfig = S['LocalCaConfig'];
export type VaultPkiConfig = S['VaultPkiConfig'];
export type KeysStatus = S['KeysStatus'];
export type RewrapStatus = S['RewrapStatus'];
export type RewrapTable = S['RewrapTable'];
export type RevocationReason = S['RevocationReason'];
export type VaultSettings = S['VaultSettings'];
export type VaultTestResult = S['VaultTestResult'];
export type ServerGrantInput = S['ServerGrantInput'];
export type ServerDeployment = S['ServerDeployment'];
export type ServerDeploymentStatus = S['ServerDeploymentStatus'];
export type RunsOn = S['RunsOn'];

// Phase 6B Task 1: alerts, monitors, events and backups. Event is aliased as
// NotifyEvent — the schema's Event would otherwise shadow the DOM Event type.
export type Channel = S['Channel'];
export type ChannelInput = S['ChannelInput'];
export type ChannelType = S['ChannelType'];
export type ChannelLastDelivery = S['ChannelLastDelivery'];
export type DeliveryResult = S['DeliveryResult'];
export type DeliveryStatus = S['DeliveryStatus'];
export type NotifyEvent = S['Event'];
export type EventPage = S['EventPage'];
export type EventKind = S['EventKind'];
export type EventDelivery = S['EventDelivery'];
export type Severity = S['Severity'];
export type Monitor = S['Monitor'];
export type MonitorInput = S['MonitorInput'];
export type MonitorState = S['MonitorState'];
export type BackupStatus = S['BackupStatus'];
export type BackupSchedule = S['BackupSchedule'];
export type SmtpTestRequest = S['SmtpTestRequest'];
export type ServerInfo = S['ServerInfo'];
