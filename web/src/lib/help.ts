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
  'flow.map': { text: 'Follows each certificate from its issuers through delivery to the clients that hold it. Select a node to trace its path.' },
  'status.pending': { text: 'Waiting for its first certificate, or for a manual DNS step.' },
  'status.active': { text: 'Holds a valid certificate and renews on schedule.' },
  'status.failed': { text: 'The last attempt failed. CertForge retries with backoff.' },
  'status.expired': { text: 'The current certificate is past its expiry date.' },
  'status.revoked': { text: 'The certificate was revoked and will not renew.' },
  'cert.validity': { text: 'Bar spans issue to expiry. Hatching marks the renewal window; the notch is now.' },
  'ca.type': {
    text: 'ACME proves control of names to a CA. Built-in CA and Vault PKI sign directly, for internal names. EAB stored means an external account binding is kept for the CA; some CAs require one.',
    learnMore: 'private-ca.md#model',
  },
  'ca.typeLocked': { text: 'The type cannot change after creation.' },
  'ca.import': {
    text: 'Use an existing issuing certificate and key instead of generating a root. Imported CAs cannot rotate.',
    learnMore: 'private-ca.md#import',
  },
  'ca.vaultPki': {
    text: 'Vault signs with this mount and role. The connection is set in Settings → Integrations.',
    learnMore: 'vault.md#pki',
  },
  'ca.preset': { text: 'Presets fill in the directory URL. Custom takes any ACME server.' },
  'ca.directoryUrl': { text: 'The ACME directory endpoint of the CA.' },
  // Renamed from 'ca.trustBundle' (task 3): that key now names the private
  // CA detail sheet's own trust-bundle download, a different field.
  'ca.importTrustBundle': { text: 'PEM roots for a private ACME server, such as step-ca or Pebble.' },
  'ca.eab': { text: 'External account binding ties orders to your account at the CA. Some CAs require it.' },
  'ca.resolvers': { text: 'DNS servers used to check propagation. Leave empty for the system resolvers.' },
  // Task 3: private CA detail sheet.
  'ca.expiry': { text: 'When the issuing certificate expires. Leaf certificates never outlive it.', learnMore: 'private-ca.md#model' },
  'ca.trustBundle': { text: 'Install on clients so they trust certificates from this CA.', learnMore: 'private-ca.md#trust' },
  'ca.retiredNoCrl': { text: 'No CRL for this issuer. CRL is off or the base URL is unset.', learnMore: 'private-ca.md#crl' },
  'ca.crl': { text: "Revocation list served without sign-in. Each leaf points at its own issuer's list.", learnMore: 'private-ca.md#crl' },
  'ca.retired': {
    text: "Earlier issuing certificates, kept until their last leaf expires. Click to copy that issuer's CRL URL.",
    learnMore: 'private-ca.md#rotation',
  },
  'ca.rotate': { text: 'Issues a new intermediate from the held root. Existing certificates stay valid.', learnMore: 'private-ca.md#rotation' },
  'ca.rotateImported': { text: 'Imported CAs have no root key here, so they cannot rotate.', learnMore: 'private-ca.md#import' },
  'account.email': { text: 'The CA sends expiry and policy notices here.' },
  'account.status': { text: 'Status is reported by the CA; only valid accounts can order certificates. The CA sends expiry and policy notices to the account email.' },
  'dns.provider': { text: 'The DNS host that serves your zone; CertForge writes TXT records there. Used by counts the certificates and issuance defaults whose verification rules use the credential.' },
  'dns.authMethod': { text: 'Some providers accept more than one kind of credential. Pick the one you have; only its fields are shown.' },
  'dns.usedBy': { text: 'Certificates and issuance defaults whose verification rules use this credential.' },
  'dns.test': { text: 'Creates and removes a test TXT record in the zone.' },
  'settings.orgs': {
    text: 'Organizations separate certificates, credentials and access. Sites are filters inside an org.',
    learnMore: 'configuration.md#general',
  },
  'settings.issuanceChecks': {
    text: 'Apply to every org. Staging CAs are counted but never blocked.',
    learnMore: 'configuration.md#issuance',
  },
  'settings.vault': {
    text: 'Connection used by Vault PKI CAs and Vault KV targets. OpenBao speaks the same API but is untested.',
    learnMore: 'vault.md#openbao',
  },
  'vault.test': {
    text: "Logs in with the values in the form and reports the token's lifetime. Nothing is saved.",
    learnMore: 'vault.md#integrations',
  },
  'vault.approle': {
    text: 'Role ID and secret ID from an AppRole with the policies in the docs.',
    learnMore: 'vault.md#approle',
  },
  'vault.transitKek': {
    text: "The key-encryption key is wrapped by this Vault's Transit engine. It is set by environment variables.",
    learnMore: 'vault.md#transit-kek',
  },
  'org.slugPermanent': { text: 'Slugs are part of every URL, so they never change.' },
  'org.deleteCascade': { text: 'Its issuance defaults and revoked-key history are removed with it.' },
  // Task 7: the Encryption key card. Replaces the now-deleted KekStatus and
  // its own 'backup.kek' entry (no longer referenced by any component).
  'keys.kind': {
    text: 'Static: a key from the environment. Vault Transit: the key never leaves Vault.',
    learnMore: 'operations.md#kek-rotation',
  },
  'keys.canary': {
    text: 'Proves the active key decrypts a known value.',
    learnMore: 'operations.md#kek-rotation',
  },
  'keys.previous': {
    text: 'Older keys still accepted for reading. Rewrap, then remove them from the environment.',
    learnMore: 'operations.md#kek-rotation',
  },
  'keys.rewrap': {
    text: 'Re-encrypts every sealed value with the active key. It resumes where it stopped.',
    learnMore: 'operations.md#rewrap',
  },
  'keys.rewrapNoPrevious': {
    text: 'Nothing to rewrap: no previous key is configured.',
    learnMore: 'operations.md#rewrap',
  },
  'defaults.caId': { text: 'CA used when a certificate does not pick one.' },
  'defaults.accountId': { text: 'ACME account used to order from that CA.' },
  // Task 4: the account field is disabled for a private effective CA.
  'defaults.accountPrivate': { text: 'ACME accounts do not apply to private CAs.', learnMore: 'certificates.md#private-ca-issuance' },
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
    text: 'Most specific wins: Certificate > Organization > Global > Built-in (shipped with CertForge). Changes apply at each certificate’s next renewal.',
    learnMore: 'configuration.md#issuance-defaults',
  },
  'defaults.globalBuiltin': {
    text: 'Most specific wins: Certificate > Organization > Global > Built-in (shipped with CertForge). Fields left unset here use the built-in value.',
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
  'cert.managed': {
    text: 'Renewed outside CertForge. Upload each new version yourself.',
    learnMore: 'certificates.md#unmanaged-certificates',
  },
  'cert.renewUnmanaged': { text: "Managed externally, so CertForge doesn't renew or edit it. Upload a new version instead." },
  'cert.uploadVersion': { text: 'Becomes the current version. Grants deploy it on their next sync.' },
  'cert.ari': {
    text: "The CA's suggested renewal window. CertForge renews inside it when that is earlier.",
    learnMore: 'certificates.md#ari',
  },
  'status.column': {
    text: 'Status is the state of the certificate itself, not of its last attempt. The validity bar spans issue to expiry: hatching marks the renewal window, the notch is now. Under each name: common name, CA, grants and any other names. ARI can move the next renewal earlier.',
  },
  'rules.method': { text: 'How each rule proves control of its names. One certificate can mix methods.', learnMore: 'certificates.md#mixing-methods' },
  'rules.match': { text: 'Name pattern. The first matching rule wins; * matches everything.' },
  'rules.credential': { text: 'DNS credential that writes the _acme-challenge TXT record.' },
  'rules.propagation': { text: 'Seconds to wait for the TXT record to spread. Empty uses the default.' },
  'rules.cnameAlias': { text: 'Zone that _acme-challenge is delegated to by CNAME.', learnMore: 'certificates.md#cname-delegation' },
  'rules.coverage': { text: 'Which rule and method prove each name. Names without one block issuing.' },
  'rules.http01': { text: 'The CA fetches a token over port 80. Wildcard names need a DNS method.', learnMore: 'certificates.md#http-01' },
  'rules.tlsalpn01': { text: 'The CA connects on port 443 and an agent answers. Wildcard names need a DNS method.', learnMore: 'certificates.md#tls-alpn-01' },
  'rules.via': { text: 'Server: CertForge answers on /.well-known/acme-challenge/. Agent: a client answers on its host.', learnMore: 'certificates.md#http-01' },
  'rules.client': { text: 'Agent that answers the challenge. Only clients that serve this method are listed, unless a webroot is set.', learnMore: 'agent.md#challenge-serving' },
  'rules.webroot': { text: 'Absolute directory on the client. The agent writes the token there instead of serving it.', learnMore: 'agent.md#challenge-serving' },
  'rules.globalAgentDisabled': { text: "Agent methods need an org's own clients, which global defaults don't have. Set this per certificate or org instead." },
  'rules.catchAll': { text: 'Rules that certificates fall back to when none of their own match.' },
  // Task 4: the wizard's Verification step, when the effective CA is private.
  'wizard.verificationNotNeeded': {
    text: 'Private CAs sign without proving control of the names.',
    learnMore: 'certificates.md#private-ca-issuance',
  },
  'wizard.verificationNeeded': { text: 'ACME CAs need each name proved. The CA chosen in Options decides this.' },
  'attempt.retry': { text: 'Failed attempts back off from 5 minutes up to 24 hours. Rate limits use the CA’s retry time.' },
  'attempt.caa': {
    text: 'CertForge checks that CAA records allow this CA before ordering. The CA checks again.',
    learnMore: 'certificates.md#caa',
  },
  'attempt.rateLedger': {
    text: 'Local counts per CA, so a limit is caught before the CA refuses.',
    learnMore: 'certificates.md#rate-limits',
  },
  'rateLedger.enforced': { text: 'Staging CAs are counted but never blocked.' },
  'manual.records': { text: 'Add these TXT records at your DNS host, then confirm. CertForge checks them before asking the CA.', learnMore: 'certificates.md#manual-dns' },
  'download.format': {
    text: 'PEM and DER suit most servers; PKCS#12 and JKS bundle the key for Windows and Java.',
    learnMore: 'certificates.md#downloads',
  },
  'download.parts': { text: 'fullchain is the certificate plus intermediates, which most servers want.' },
  'download.derParts': { text: 'DER holds one item per file. fullchain and combined exist only as PEM.' },
  'download.key': { text: 'Private key downloads are recorded in the audit log.' },
  'download.password': {
    text: 'Protects the file. It is never stored or logged, so copy it before downloading.',
    learnMore: 'certificates.md#export-passwords',
  },
  'download.ownPassword': { text: 'Off generates a 24-character password. JKS needs at least 6 characters.' },
  'download.encoding': { text: 'Modern uses AES and SHA-256. Legacy uses 3DES for old Windows and Java.' },
  'download.alias': { text: 'Name of the key entry in the keystore. Empty uses the certificate name.' },
  'download.noKey': { text: 'This version has no stored private key, so only certificate parts are available.' },
  'cert.versions': { text: 'Every certificate issued for this entry. The dashed segment is the successor.' },
  // Task 5: revoking a private-CA certificate version.
  'version.revoke': { text: "Adds this version to the CA's revocation list. It cannot be undone.", learnMore: 'private-ca.md#revocation' },
  'version.revokeReason': {
    text: 'Recorded in the CRL entry. Use Key compromise if the private key leaked.',
    learnMore: 'private-ca.md#revocation',
  },
  'overview.horizon': {
    text: 'One tick per certificate at its expiry, coloured by state. Drag across the strip to list a range.',
    learnMore: 'web-ui.md#overview',
  },
  'overview.page': { text: 'Certificate health at a glance: status counts, what needs attention, upcoming expiries and recent activity.', learnMore: 'web-ui.md#overview' },
  'overview.attention': { text: 'Expired, waiting on you, failing, overdue, not deployed or offline, most urgent first.', learnMore: 'web-ui.md#overview' },
  'attention.monitor': { text: 'An external monitor sees the wrong certificate or cannot connect.', learnMore: 'monitoring.md#states' },
  'cert.grants': { text: 'Clients this certificate is granted to.' },
  'cert.deployments': { text: 'One row per client holding this certificate, with what its agent installed.', learnMore: 'agent.md#grants-and-reconcile' },
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
  'client.connection': { text: 'Online means the agent is connected or pulled within the offline threshold. Offline clients catch up when they reconnect or pull.', learnMore: 'agent.md#troubleshooting' },
  'client.status': { text: 'Pending is not yet enrolled or waits on a new token; Active holds an agent certificate. Revoked is refused but kept for its history.' },
  'deploy.pending': { text: 'Waiting for the agent to install the current version.' },
  'deploy.ok': { text: 'The agent installed the current version and the files still match.' },
  'deploy.failed': { text: 'The agent reported an error. It tries again on the next change or redeploy.' },
  'deploy.drift': { text: 'Files on the host changed or went missing after the deploy.', learnMore: 'agent.md#drift' },
  'client.name': { text: 'Unique in this org. Shown in lists and audit events.' },
  'client.site': { text: 'Sites group clients for filtering. They never limit access.' },
  'client.agentVersion': { text: 'certforge-agent version the host reported when it last connected.' },
  'client.grants': { text: 'Certificates granted to this client.' },
  'client.drift': { text: 'Grants whose files on the host no longer match, and grants whose last deploy failed.', learnMore: 'agent.md#drift' },
  'client.lastSeen': { text: 'Last connection, heartbeat or report from the agent.' },
  'client.token': { text: 'Single use and shown only now. Start the agent with it before it expires.', learnMore: 'agent.md#enrolment' },
  'client.snippet': { text: 'Runs the agent with a volume for its identity. Edit CF_WRITE_ALLOW and the mount to match your deploy directory.', learnMore: 'agent.md#running-with-docker' },
  'client.waiting': { text: 'The agent enrols with the token, then connects. This updates by itself.', learnMore: 'agent.md#troubleshooting' },
  'client.agentCert': { text: 'The agent’s own identity certificate. It renews itself at two thirds of its lifetime.', learnMore: 'agent.md#enrolment' },
  'client.capabilities': { text: 'Features the agent reported, such as traefik and hooks.' },
  'client.reenroll': { text: 'Issues a new token and disconnects the agent until it enrols again. Use it after rebuilding the host.', learnMore: 'agent.md#enrolment' },
  'client.revoke': { text: 'Refuses the agent’s certificate and closes its connection. Files already on the host stay; grants still waiting for removal are dropped.' },
  'client.delete': { text: 'Only revoked clients, or clients that never enrolled, can be deleted.' },
  'grant.certificates': { text: 'Pick one or more certificates. Each becomes its own grant with the settings below.', learnMore: 'agent.md#grants-and-reconcile' },
  'grant.delivery': {
    text: 'Push sends changes at once over the connection. Pull waits for the agent’s schedule or a manual certforge-agent pull, and shows a warning for the delay.',
    learnMore: 'agent.md#pull-mode',
  },
  'grant.pullWarning': {
    text: 'Pull grants get no push from the server. With CF_AGENT_PULL_INTERVAL=0 they deploy only when the agent reconnects or runs pull.',
    learnMore: 'agent.md#pull-mode',
  },
  'grant.layout': { text: 'Files the agent writes, built from PEM parts.', learnMore: 'agent.md#file-layouts' },
  'grant.target': { text: 'What the agent does besides writing files, such as updating Traefik.', learnMore: 'deploy-targets.md#traefik' },
  'grant.hooks': { text: 'Commands the agent runs around the deploy, in the numbered order. Reorder them with the arrows.', learnMore: 'agent.md#hooks-and-the-allowlist' },
  'grant.autoRemediate': { text: 'On drift, reinstall the files automatically instead of only reporting it.', learnMore: 'agent.md#drift' },
  'grant.files': { text: 'Expected digests come from the server; installed ones from the agent’s last report.', learnMore: 'agent.md#drift' },
  'grant.forceRemove': { text: 'Deletes the grant now and leaves any files on the host for the agent to clean up later. Use it when the agent is gone for good.' },
  // Task 8: server-run targets and their grants (grant.serverTarget disables
  // a server-run target in the client grant sheet; serverDeployment.status
  // covers ServerDeploymentChip).
  'grant.serverTarget': { text: 'Server-run targets need no client. Grant them from the target’s detail.', learnMore: 'deploy-targets.md#runs-on' },
  'serverDeployment.status': {
    text: 'Pending is queued and Deployed is written. Failed shows the error, and Redeploy retries.',
    learnMore: 'deploy-targets.md#vault-kv',
  },
  'deploy.redeploy': { text: 'Asks the agent to reinstall the current version and report again.' },
  'hook.exit': { text: 'Exit status. -1 means the agent refused it, it failed to start, or it timed out.', learnMore: 'agent.md#hooks-and-the-allowlist' },
  'target.type': { text: 'What the target updates. Its fields come from the type’s schema.', learnMore: 'deploy-targets.md#deploy-targets' },
  'target.runsOn': { text: 'Server: CertForge pushes each version itself. Agent: a client on the host does it.', learnMore: 'deploy-targets.md#runs-on' },
  // 7B Task 1 (R12): the type segment's own disabled hint when a type can
  // only run one way, and the runs-on control's hint once a target exists
  // (immutable after create — Shared contracts, R3).
  'target.runsOnForced': { text: 'This type can only run here.', learnMore: 'deploy-targets.md#runs-on' },
  'target.runsOnLocked': { text: 'Fixed once the target exists. Create a new target to change it.', learnMore: 'deploy-targets.md#runs-on' },
  'target.secrets': { text: 'Secret fields are stored encrypted and never shown again. Leave one untouched to keep it.', learnMore: 'deploy-targets.md#secrets' },
  'target.vaultKv': { text: 'CertForge writes the files to Vault KV itself. No client is involved.', learnMore: 'deploy-targets.md#vault-kv' },
  'target.includeKey': { text: 'Also send the private key. On the server this needs the keys:export permission.', learnMore: 'deploy-targets.md#vault-kv' },
  'target.usedBy': { text: 'Grants that use it. Remove those grants before deleting.' },
  // Task 9: the deploy-target detail sheet's own Grants section and its
  // server grant form's Layout field.
  'grant.server': { text: 'CertForge pushes each new version to this target itself.', learnMore: 'deploy-targets.md#runs-on' },
  'grant.serverLayout': {
    text: "Optional; without one, the target's own key names are used. Only PEM layouts work here.",
    learnMore: 'deploy-targets.md#vault-kv',
  },
  'layout.path': { text: 'Absolute path on the client host, one per file.', learnMore: 'agent.md#file-layouts' },
  'layout.parts': { text: "Joined in the order picked. extra adds each extra certificate's leaf and chain." },
  'layout.format': {
    text: 'PEM joins parts. DER holds one part; PKCS#12 and JKS hold the certificate, chain and key.',
    learnMore: 'agent.md#file-layouts',
  },
  'layout.derPart': { text: 'A DER file holds exactly one item: the certificate or the key.' },
  'layout.password': {
    text: 'Protects PKCS#12 and JKS files. Stored encrypted and never shown again.',
    learnMore: 'certificates.md#export-passwords',
  },
  'layout.passwordNeeded': { text: 'A PKCS#12 or JKS file in this layout still needs it. Change that file to PEM or DER first.' },
  'layout.extraCerts': {
    text: "Other certificates added to this layout's files, such as a partner CA. Up to 10.",
    learnMore: 'agent.md#file-layouts',
  },
  'layout.owner': { text: 'User name or uid. Applied only when the agent runs as root.' },
  'layout.group': { text: 'Group name or gid. Applied only when the agent runs as root.' },
  'layout.mode': { text: 'Octal permissions, such as 0640.' },
  'layout.keyMode': { text: 'This file holds a private key and every user on the host can read it. Use 0640 or tighter.' },
  'hook.phase': { text: 'Pre-deploy runs before files are written, and a failure stops the deploy. Post-deploy runs after.' },
  'hook.argv': { text: 'The executable, then one argument per row. It never runs through a shell.', learnMore: 'agent.md#hooks-and-the-allowlist' },
  'hook.allowlist': { text: 'Agents run a hook only when this exact path is in their CF_HOOK_ALLOW. Otherwise the run is refused.', learnMore: 'agent.md#hooks-and-the-allowlist' },
  'hook.timeout': { text: 'The hook and its child processes are stopped after this long.' },
  'agents.agentUrl': { text: 'Only new enrolments pick up a changed URL. Already-enrolled agents keep the URL they enrolled with; re-enrol them to move them.', learnMore: 'configuration.md#agents' },
  'agents.listener': { text: 'The certificate agents see on the agent port, signed by the oldest agent CA not yet retired. It renews itself.', learnMore: 'configuration.md#agents' },
  'agents.listenerNotRunning': { text: 'Restart the server after fixing the cause.', learnMore: 'configuration.md#agents' },
  'agents.ca': { text: 'Signs every agent’s identity certificate. After a rotation the old CA stays trusted until you retire it.', learnMore: 'operations.md#agent-ca-rotation' },
  'agents.activeCerts': { text: 'Unexpired certificates of active clients signed by this CA.' },
  'agents.rotate': { text: 'New agent certificates and renewals come from the new CA. Unused tokens keep working until the old CA is retired.', learnMore: 'operations.md#agent-ca-rotation' },
  'agents.retire': { text: 'Stops trusting this CA. Allowed once no agent certificate from it is still in use.', learnMore: 'operations.md#agent-ca-rotation' },
  'import.menu': {
    text: 'Import takes over renewal from acme.sh or certbot. Upload stores a certificate renewed elsewhere.',
    learnMore: 'certificates.md#import',
  },
  'upload.certificate': { text: 'The leaf certificate first, then its chain, as PEM.' },
  'upload.key': {
    text: 'Optional. Without it the certificate can go only to layouts without key files.',
    learnMore: 'certificates.md#upload',
  },
  'upload.pkcs12': { text: 'A .p12 or .pfx file with the certificate, chain and usually the key. Up to 768 KiB.' },
  'upload.password': { text: 'The password the PKCS#12 file was exported with.' },
  'import.archive': {
    text: 'A zip or tar.gz of ~/.acme.sh or /etc/letsencrypt, up to 32 MiB.',
    learnMore: 'certificates.md#import',
  },
  'import.ca': { text: 'The CA that renews these certificates from now on. It needs an ACME account in this org.' },
  'import.action': { text: 'Create adds the certificate. Skip gives the reason, such as a name already in use.' },
  'import.hasKey': { text: "Without a key the certificate can't be deployed with key files until its first renewal." },
  // Task 2 (Phase 6B): the Alerts area — tabs, channels table.
  'alerts.channels': {
    text: 'Where CertForge sends events: webhooks, email, chat and push services. Last delivery is the most recent result, tests included. An All orgs channel receives events from every organization; only a global admin can set it.',
    learnMore: 'notifications.md#channels',
  },
  'channel.allOrgs': {
    text: 'Receives events from every organization. Only a global admin can set it.',
    learnMore: 'notifications.md#channels',
  },
  'channel.lastDelivery': {
    text: 'Result of the most recent delivery to this channel, tests included.',
    learnMore: 'notifications.md#events',
  },
  'channel.limit': { text: 'An organization can have at most 50 channels.' },
  'alerts.monitors': {
    text: 'Checks which certificate a TLS endpoint serves and alerts when it changes. State comes from the last check: OK, Mismatch, Expiring (under 14 days) or Unreachable. The check button runs one now.',
    learnMore: 'monitoring.md#external-monitors',
  },
  'alerts.events': {
    text: 'Events from the last 90 days and where each one was delivered.',
    learnMore: 'notifications.md#events',
  },
  // Task 3 (Phase 6B): the channel sheet and Send test.
  'channel.type': {
    text: 'How the channel delivers events. The type is fixed once the channel exists.',
    learnMore: 'notifications.md#channels',
  },
  'channel.events': {
    text: 'Only these events are sent. With none selected, every event is sent.',
    learnMore: 'notifications.md#events',
  },
  'channel.minSeverity': {
    text: 'Events below this severity are not sent to this channel.',
    learnMore: 'notifications.md#events',
  },
  'channel.enabled': { text: 'A disabled channel gets no events. Send test still works.' },
  'channel.test': {
    text: 'Sends a test event to the saved channel now and shows the result.',
    learnMore: 'notifications.md#channels',
  },
  'channel.testSaved': { text: 'Tests the saved channel. Save your changes first.' },
  'notifier.webhook': {
    text: 'Posts each event as JSON. A signing secret lets the receiver verify it.',
    learnMore: 'notifications.md#signature',
  },
  'notifier.smtp': {
    text: 'Sends plain-text email through the SMTP server in Settings → Integrations.',
    learnMore: 'notifications.md#smtp',
  },
  'notifier.discord': {
    text: 'Posts one embed per event to a Discord channel webhook.',
    learnMore: 'notifications.md#discord',
  },
  'notifier.ntfy': {
    text: 'Publishes to an ntfy topic, with priority set by severity.',
    learnMore: 'notifications.md#ntfy',
  },
  'notifier.homeassistant': {
    text: 'Triggers a Home Assistant webhook automation with the event JSON.',
    learnMore: 'notifications.md#home-assistant',
  },
  // Task 4 (Phase 6B): external monitors.
  'monitor.state': {
    text: 'From the last check: OK, Mismatch, Expiring (under 14 days) or Unreachable.',
    learnMore: 'monitoring.md#states',
  },
  'monitor.expected': {
    text: 'The certificate this endpoint should serve. Without one, any CertForge certificate matches.',
    learnMore: 'monitoring.md#states',
  },
  'monitor.sni': { text: 'Server name sent in the TLS handshake. Empty means the host.' },
  'monitor.interval': { text: 'How often CertForge checks the endpoint.', learnMore: 'monitoring.md#external-monitors' },
  'monitor.check': { text: 'Checks the endpoint now and updates its state.', learnMore: 'monitoring.md#external-monitors' },
  'monitor.limit': { text: 'An organization can have at most 500 monitors.' },
  // Task 5 (Phase 6B): the events log.
  'event.severity': { text: 'Shows events at or above this severity.', learnMore: 'notifications.md#events' },
  // Task 6 (Phase 6B): Settings → Integrations' Email, Notifications and
  // Prometheus sections.
  'settings.smtp': { text: 'Mail server used by email channels and the test email.', learnMore: 'configuration.md#smtp-section' },
  'smtp.testSaved': { text: 'Sends one message using the saved settings. Save your changes first.', learnMore: 'notifications.md#smtp' },
  'smtp.needsHost': { text: 'Save an SMTP host first.', learnMore: 'configuration.md#smtp-section' },
  'settings.notifications': { text: 'Applies to every channel: URL policy, expiry warning and failure threshold.', learnMore: 'configuration.md#notifications-section' },
  'settings.prometheus': { text: 'Serves /metrics for Prometheus behind a bearer token.', learnMore: 'configuration.md#prometheus-section' },
  'prometheus.scrape': { text: 'Scrape this URL with the token as a bearer credential. The token never goes in the URL.', learnMore: 'monitoring.md#metrics-reference' },
  // Task 7 (Phase 6B): Settings → Backup and keys' status card, actions and schema.
  'backup.status': {
    text: 'Result of the last backup the server wrote on its schedule.',
    learnMore: 'operations.md#backup-schedule',
  },
  'backup.now': {
    text: 'Downloads an encrypted archive of the database. Restoring it needs the same KEK.',
    learnMore: 'operations.md#backup',
  },
  'backup.needsEscrow': {
    text: 'Confirm the KEK is stored safely first. Without it no backup can be restored.',
    learnMore: 'operations.md#backup',
  },
  'backup.restore': {
    text: 'Restore runs offline with certforge restore while the server is stopped.',
    learnMore: 'operations.md#restore',
  },
  'settings.backup': {
    text: 'Scheduled backups go to a directory on the server, keeping the newest files.',
    learnMore: 'configuration.md#backup-section',
  },
} satisfies Record<string, Help>;

export type HelpKey = keyof typeof help;
