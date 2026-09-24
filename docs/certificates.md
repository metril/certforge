# Certificates

How CertForge obtains certificates: CAs, ACME accounts, verification, defaults, renewal and downloads.

## Certificate authorities

Issuers → CAs. Pick a preset or Custom.

| Preset | Directory | EAB |
|---|---|---|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` | no |
| `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | no |
| `zerossl` | `https://acme.zerossl.com/v2/DV90` | required |
| `buypass` | `https://api.buypass.com/acme/directory` | no |
| `google` | `https://dv.acme-v02.api.pki.goog/directory` | required |
| `sslcom` | `https://acme.ssl.com/sslcom-dv-rsa` | required |
| `custom` | any `https://` directory URL | optional |

- **Trust bundle**: PEM roots added to the system pool when talking to a private ACME server (Pebble, step-ca, Vault ACME).
- **Resolvers**: `host` or `host:port` DNS servers used for propagation checks when neither the rule nor the defaults name any.
- Only a global admin (`cas:write`) adds or edits CAs. In Phase 1 a CA row belongs to one org; shared global CAs arrive in Phase 2.
- A CA cannot be deleted while accounts, certificates or defaults reference it.

### External Account Binding (EAB)

ZeroSSL, Google Trust Services and SSL.com require EAB. Create the key id and HMAC in the CA's console, then enter them on the CA. The HMAC is write-only: the API reports `hasEab` and never returns it. On update, leave it empty or send `__unchanged__` to keep it; send an empty string to remove it.

## ACME accounts

Issuers → ACME accounts → Register. CertForge generates a P-256 account key, registers it at the CA (with the CA's EAB), and stores the key envelope-encrypted. The registration URI is the account's `kid`. Deleting an account removes it from CertForge only; it is not deactivated at the CA. Accounts referenced by certificates or defaults cannot be deleted.

## Defaults and overrides

Every issuance field exists at three levels: global (Settings → Issuance defaults), org, and certificate. A null value inherits from the level above; unset globals fall back to built-in values.

| Field | Built-in | Notes |
|---|---|---|
| `caId`, `accountId` | none | Issuance fails with a clear error until both are set somewhere. The account must belong to the CA. |
| `keyType` | `ec256` | `rsa2048`, `rsa3072`, `rsa4096`, `ec256`, `ec384`. |
| `renewPolicy` | `percent`, 33 | See [Renewal](#renewal). |
| `preferredChain` | empty | Issuer common name of an alternate chain. |
| `reuseKey` | off | Keeps the private key across renewals when the key type is unchanged. |
| `mustStaple` | off | Adds the OCSP must-staple extension. |
| `verificationRules` | none | Catch-all rules appended after a certificate's own rules. |
| `propagationSeconds` | 120 | How long to wait for TXT records. |
| `resolvers` | none | Resolvers for propagation checks. |

`GET /api/v1/orgs/{orgId}/issuance-defaults/effective` and each certificate's `effective` field show the resolved value and its `source`: `default` (built-in), `global`, `org` or `cert`. A changed default applies at the next renewal of every certificate that inherits it. Saving the global section (`PUT /settings/issuance_defaults`) and org defaults (`PUT /orgs/{orgId}/issuance-defaults`) both validate that a referenced CA, account or DNS credential exists (and, for org defaults, belongs to the org) before storing; an unknown id is a 422.
