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
  'settings.orgs': { text: 'Organizations visible to your account. Full org management arrives in a later phase.' },
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
} satisfies Record<string, Help>;

export type HelpKey = keyof typeof help;
