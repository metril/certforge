export type Help = { text: string; learnMore?: `${string}.md#${string}` };

export const DOCS_BASE: string =
  (import.meta.env.VITE_DOCS_BASE as string | undefined) ?? 'https://github.com/metril/certforge/blob/main/docs/';

export function docsHref(ref: string): string {
  return DOCS_BASE + ref;
}

export function firstSentences(text: string, n: number): string {
  // Split only where punctuation is followed by whitespace, so "Zone.DNS" stays one word.
  return text.trim().split(/(?<=[.!?])\s+/).slice(0, n).join(' ');
}

// One entry per field id. At most two short sentences. Later tasks add entries here.
export const help = {
  'login.password': { text: 'The local admin password set during first-run setup.' },
  'login.sso': {
    text: 'Signs you in through your organisation’s identity provider.',
    learnMore: 'configuration.md#authentication',
  },
  'login.breakGlass': { text: 'The local admin password, for when single sign-on is unavailable.' },
  'setup.adminPassword': { text: 'Break-glass login for the local admin. Use at least 12 characters.' },
  'setup.baseUrl': { text: 'The address people and agents use to reach CertForge. Links in notifications use it.' },
  'setup.kek': {
    text: 'CertForge encrypts private keys with a key from its environment. It must load before setup can finish.',
    // Adaptation (preflight D7): docs/configuration.md already has a
    // "## First-run setup wizard" heading; point at it instead of adding a
    // near-duplicate "## First-run setup" heading (GitHub would slug the
    // second one "-1" and break this anchor).
    learnMore: 'configuration.md#first-run-setup-wizard',
  },
  'setup.orgSlug': { text: 'Short name used in URLs. Lowercase letters, digits, and hyphens.' },
  'status.pending': { text: 'Waiting for its first certificate, or for a manual DNS step.' },
  'status.active': { text: 'Holds a valid certificate and renews on schedule.' },
  'status.failed': { text: 'The last attempt failed. CertForge retries with backoff.' },
  'status.expired': { text: 'The current certificate is past its expiry date.' },
  'status.revoked': { text: 'The certificate was revoked and will not renew.' },
  'cert.validity': { text: 'Bar spans issue to expiry. Hatching marks the renewal window; the notch is now.' },
  'ca.preset': { text: 'Presets fill in the directory URL. Custom takes any ACME server.' },
  'ca.directoryUrl': { text: 'The ACME directory endpoint of the CA.' },
  'ca.trustBundle': { text: 'PEM roots for a private ACME server, such as step-ca or Pebble.' },
  'ca.eab': { text: 'External account binding ties orders to your account at the CA. Some CAs require it.' },
  'ca.resolvers': { text: 'DNS servers used to check propagation. Leave empty for the system resolvers.' },
  'account.email': { text: 'The CA sends expiry and policy notices here.' },
  'account.status': { text: 'Status reported by the CA. Only valid accounts can order certificates.' },
  'dns.provider': { text: 'The DNS host that serves your zone. CertForge writes TXT records there.' },
  'dns.usedBy': { text: 'Certificates and issuance defaults whose verification rules use this credential.' },
  'dns.test': { text: 'Creates and removes a test TXT record in the zone.' },
  'settings.orgs': {
    text: 'Organizations separate certificates, credentials and access. Sites are filters inside an org.',
    learnMore: 'configuration.md#general',
  },
  'org.slugPermanent': { text: 'Slugs are part of every URL, so they never change.' },
  'org.deleteCascade': { text: 'Its issuance defaults and revoked-key history are removed with it.' },
  'backup.kek': {
    text: 'Whether the key-encryption key is loaded and passes its startup check.',
    learnMore: 'configuration.md#the-kek',
  },
  'defaults.caId': { text: 'CA used when a certificate does not pick one.' },
  'defaults.accountId': { text: 'ACME account used to order from that CA.' },
  'defaults.keyType': { text: 'Key algorithm for new certificates. EC P-256 is small and widely supported.' },
  'defaults.renewPolicy': {
    text: 'Days: renew this many days before expiry. Percent: renew once this share remains, never before half the lifetime.',
    learnMore: 'configuration.md#issuance-defaults',
  },
  'defaults.useAri': { text: 'Let the CA suggest the renewal window (ACME Renewal Information).' },
  'defaults.preferredChain': { text: 'Common name of the root to prefer when the CA offers several chains.' },
  'defaults.reuseKey': { text: 'Keep the same private key across renewals. Needed for key pinning.' },
  'defaults.mustStaple': { text: 'Ask the CA to set OCSP Must-Staple. Only use it if every server staples.' },
  'defaults.propagationSeconds': { text: 'How long to wait for TXT records to reach every nameserver.' },
  'defaults.resolvers': { text: 'DNS servers used to check propagation. Empty means system resolvers.' },
  'defaults.inherit': {
    text: 'Unset fields inherit from the level above. Changes apply at each certificate’s next renewal.',
    learnMore: 'configuration.md#issuance-defaults',
  },
  'defaults.globalBuiltin': {
    text: "Fields left as Default follow the server's built-in values.",
    learnMore: 'configuration.md#issuance-defaults',
  },
  'cert.names': {
    text: 'Paste names separated by commas, spaces, semicolons, or new lines. Wildcards need DNS verification.',
    learnMore: 'certificates.md#names',
  },
  'cert.cn': { text: 'Shown as the subject of the certificate. Drag a name here or use its crown button.', learnMore: 'certificates.md#names' },
  'cert.wildcardMarker': {
    text: 'A wildcard can only be proven with DNS verification (dns-01 or manual-dns), never HTTP-01.',
    learnMore: 'certificates.md#names',
  },
  'cert.ipMarker': {
    text: 'Phase 1 cannot validate IP names (dns-01 and manual-dns only), so the certificate will fail until HTTP-01 lands.',
    learnMore: 'certificates.md#names',
  },
  // Fix round 1 (review): the list column needs its own key — `cert.names`
  // is wizard copy about pasting names into the create-certificate step
  // (Task 12), not what a read-only SANs column means.
  'cert.namesColumn': { text: 'Subject alternative names besides the common name shown under Name.', learnMore: 'certificates.md#names' },
  'cert.nextRenew': { text: 'When CertForge next tries to renew. ARI can move it earlier.' },
  'status.column': { text: 'State of the certificate itself, not of its last attempt.' },
  'rules.method': { text: 'How you prove control of each name. One method per certificate in this version.', learnMore: 'certificates.md#verification-rules' },
  'rules.match': { text: 'Name pattern. The first matching rule wins; * matches everything.' },
  'rules.credential': { text: 'DNS credential that writes the _acme-challenge TXT record.' },
  'rules.propagation': { text: 'Seconds to wait for the TXT record to spread. Empty uses the default.' },
  'rules.cnameAlias': { text: 'Zone that _acme-challenge is delegated to by CNAME.', learnMore: 'certificates.md#cname-delegation' },
  'rules.coverage': { text: 'Which rule proves each name. Names without one block issuing.' },
  'rules.catchAll': { text: 'Rules that certificates fall back to when none of their own match.' },
  'attempt.retry': { text: 'Failed attempts back off from 5 minutes up to 24 hours. Rate limits use the CA’s retry time.' },
  'manual.records': { text: 'Add these TXT records at your DNS host, then confirm. CertForge checks them before asking the CA.', learnMore: 'certificates.md#manual-dns' },
  'download.format': { text: 'PEM is text, used by most servers. Other formats arrive in a later phase.' },
  'download.parts': { text: 'fullchain is the certificate plus intermediates, which most servers want.' },
  'download.key': { text: 'Private key downloads are recorded in the audit log.' },
  'cert.versions': { text: 'Every certificate issued for this entry. The dashed segment is the successor.' },
  'overview.horizon': {
    text: 'One tick per certificate at its expiry, coloured by state. Drag across the strip to list a range.',
    learnMore: 'web-ui.md#overview',
  },
  'overview.attention': { text: 'Expired, waiting on you, failing, or overdue, most urgent first.', learnMore: 'web-ui.md#overview' },
  'overview.activity': { text: 'The last 20 audit events here. Open one to see what changed.', learnMore: 'web-ui.md#audit-log' },
  'user.source': { text: 'The identity provider that signed the user in, or Local for the break-glass admin.' },
  'user.groups': { text: 'Groups from the user’s last single sign-on. Group bindings match these.' },
  'user.status': { text: 'Disabling signs the user out everywhere and stops their API keys.', learnMore: 'configuration.md#access' },
  'user.self': { text: 'You can’t disable your own account.' },
  'binding.subjectType': { text: 'Who gets the role: a user, a group from single sign-on, or an API key.' },
  'binding.group': { text: 'The group name exactly as the identity provider sends it in the groups claim.', learnMore: 'configuration.md#authentication' },
  'binding.role': { text: 'Viewer reads, auditor also reads the audit log, operator issues and edits certificates. Org admin runs one org; admin runs everything.' },
  'binding.scope': { text: 'One org, or All orgs for a global role. Changes apply on the next request.' },
  'binding.userDisabled': { text: 'You need bindings:write to add user bindings.' },
  'binding.groupDisabled': { text: 'Only a global admin can add group mappings.' },
  'binding.apikeyDisabled': { text: 'You need apikeys:write to add API key bindings.' },
  'binding.apikey': { text: 'Narrows what the key can do; it never goes beyond its creator.' },
  'auth.redirectUri': { text: 'Register this exact URI for the CertForge client at your identity provider.', learnMore: 'configuration.md#authentication' },
  'auth.groupMappings': { text: 'Give every member of an identity provider group a role. Same as a group binding in Access.' },
  'apikey.scopes': {
    text: 'What the key may do; never more than you can do in its scope. Greyed-out permissions are outside your role.',
    learnMore: 'security.md#api-keys',
  },
  'apikey.org': { text: 'Limit the key to one org, or All orgs for a key that follows your global role.' },
  'apikey.expiry': { text: 'The key stops working after this. Revoke it any time.' },
  'apikey.prefix': { text: 'The public part of the token. Match it against logs and scripts.' },
  'apikey.status': { text: 'Keys also stop working when their creator is disabled.' },
  'apikey.secretOnce': { text: 'Copy it now; it is never shown again. Only its hash is kept, so a lost key needs a new one.' },
  'orgs.allOrgs': { text: 'Every org you can read, in one view. Switch to one org to make changes.' },
  'audit.chain': { text: 'Every event is linked to the previous one with a keyed hash. Verified means nothing was edited or removed.', learnMore: 'security.md#audit-log' },
  'audit.chainBroken': { text: 'An event no longer matches its hash: the log was altered outside CertForge.', learnMore: 'security.md#audit-log' },
  'audit.actor': { text: 'The user or API key that acted; system for scheduled work.' },
  'audit.ip': { text: 'Client address, taken from X-Forwarded-For only behind a trusted proxy.' },
  'audit.exportError': { text: 'A query failed partway through the export; the downloaded file is missing events after that point. Try again, or narrow the filters.' },
  'audit.missingEvent': { text: "The linked event doesn't exist, or your role can't read it." },
  'audit.exportTruncated': { text: 'The export hit the 100,000-row cap; narrow the filters to get every matching event.' },
} satisfies Record<string, Help>;

export type HelpKey = keyof typeof help;
