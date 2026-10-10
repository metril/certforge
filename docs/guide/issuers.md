# Issuers

An issuer is whatever signs your certificates. CertForge supports three kinds of certificate authority (CA): **ACME** (Let's Encrypt, ZeroSSL and others), a **Built-in CA** that CertForge runs itself, and **Vault PKI**, which signs through your Vault or OpenBao. **Issuers** has three tabs: **CAs**, **ACME accounts** and **DNS credentials** (see [Challenges](challenges.md#dns-01)).

## Before you start

- Adding, editing, rotating and deleting CAs needs `cas:write`, which only global admins have. Everyone with `cas:read` can view them.
- Registering and deleting ACME accounts needs `accounts:write` (operators and org admins).
- Vault PKI needs the Vault integration first: [Vault](vault.md).

## Add an ACME CA

1. Open **Issuers → CAs** and select **Add CA**. **Type** is **ACME**.
2. Enter a **Name** and pick a **Preset** card. A preset fills in the directory URL.
3. If the card shows an **EAB** badge, enter the **Key ID** and **HMAC key** from the CA's console (see [EAB](#external-account-binding)).
4. Select **Save CA**.

| Preset | Directory | EAB |
|---|---|---|
| **Let's Encrypt** | `https://acme-v02.api.letsencrypt.org/directory` | no |
| **Let's Encrypt (staging)** | `https://acme-staging-v02.api.letsencrypt.org/directory` | no |
| **ZeroSSL** | `https://acme.zerossl.com/v2/DV90` | required |
| **Buypass Go SSL** | `https://api.buypass.com/acme/directory` | no |
| **Google Trust Services** | `https://dv.acme-v02.api.pki.goog/directory` | required |
| **SSL.com** | `https://acme.ssl.com/sslcom-dv-rsa` | required |
| **Custom directory** | any `https://` ACME directory | optional |

With **Custom directory**, enter the **Directory URL** and, for a private ACME server such as step-ca or Pebble, paste its roots into **Trust bundle**. **Advanced → Resolvers** sets the DNS servers used for propagation checks for this CA.

CertForge validates the directory URL when you save it: the hostname must resolve, loopback and cloud-metadata addresses are refused, and private (RFC 1918) addresses are allowed. See [URL policy](../operations/security-model.md).

### External account binding

ZeroSSL, Google Trust Services and SSL.com require EAB. Create a key ID and HMAC key in the CA's console and enter them on the CA. The HMAC key is write-only: CertForge shows "EAB stored" and never returns it. When you edit the CA, leave the field untouched to keep it.

## Register an ACME account

An ACME CA needs an account before it can issue.

1. Open **Issuers → ACME accounts** and select **Register account**.
2. Pick the **Certificate authority** and enter a **Contact email**. The CA sends expiry and policy notices there.
3. Select **Register**.

CertForge generates a P-256 account key, registers it at the CA (with the CA's EAB) and stores the key encrypted. The list shows the **Status** (**Valid** when the CA accepts it) and a copyable **Registration** URI. Deleting an account removes it from CertForge only; it is not deactivated at the CA. An account used by certificates or defaults cannot be deleted. Private CAs need no account.

## Delete or edit a CA

Use the row's edit and delete buttons on **CAs**. Deleting is refused while accounts, certificates or defaults use the CA. A private CA also cannot be deleted while it has issued versions that are neither expired nor revoked: revoke them or wait for them to expire. A Vault PKI CA's mount and role cannot change while it is in use.

## Model

A **Built-in CA** is two certificates:

- A **root**, self-signed, that may sign one layer of intermediate. Its key is kept sealed and used only to [rotate](#rotation).
- An **issuing intermediate**, signed by the root. It signs every leaf and every CRL. Its common name gets a date and serial suffix, for example `Acme Corp Issuing CA 2026-01-3fa9c1d2`, so rotations stay distinguishable.

A leaf lives for the shorter of **Max leaf validity (days)** and what remains of the issuing certificate, so it never outlives its issuer. Leaves carry the `serverAuth` and `clientAuth` uses and, when **Base URL** is set in **Settings → General**, a CRL distribution point.

### Create a Built-in CA

1. On **CAs**, select **Add CA** and set **Type** to **Built-in CA**.
2. Enter a **Name**. Under **Subject**, enter a **Common name** (required), optionally **Organization** and a two-letter **Country**.
3. Choose the **Key type** (EC P-256, EC P-384, RSA 2048 or RSA 4096; default EC P-256).
4. Set validity: **Root validity (years)** (1 to 30, default 10) and **Issuing validity (years)** (1 to 10, default 3).
5. Set **Max leaf validity (days)** (1 to 825, default 397) and leave **Publish CRL** on to publish a revocation list.
6. Select **Save CA**.

Subject, key type and both validities are fixed after creation. **Max leaf validity (days)** and **Publish CRL** can be edited later.

## Import

To use your own issuing certificate instead of generating a root, turn on **Import existing CA** on a new Built-in CA. Paste the **Import: certificate chain** (the issuing certificate first, then its chain in order) and the **Import: private key**. The key is never shown again.

Requirements:

- The issuing certificate is a valid CA with certificate-signing use, and the key matches it.
- Each certificate is signed by the next one in the chain.
- Keys are RSA 2048 or larger, or ECDSA P-256, P-384 or P-521. No MD5 or SHA-1 signatures (a self-signed root's own signature is exempt).
- With **Publish CRL** on, the issuing certificate must be able to sign CRLs, otherwise the save fails with "issuing certificate cannot sign CRLs".

CertForge holds no root key for an imported CA, so it cannot [rotate](#rotation). The CA detail shows an **Imported** chip. The **Trust bundle** is the last certificate of the chain you supplied.

## Rotation

Rotation replaces the issuing intermediate before it expires, without touching the root or any issued certificate.

1. Select the CA on **CAs** to open its detail.
2. Select **Rotate issuing certificate** and confirm.

CertForge signs a new intermediate under the same root. New certificates use it; existing ones stay valid and keep verifying. The old intermediate and its key are retired, not deleted: they are kept until their own expiry so leaves they signed can still be revoked and their CRL still served. Retired issuers appear under **Retired issuers**. Rotation needs `cas:write`, a generated root that is not expired, and is not available for imported CAs or Vault PKI. It is recorded as `ca.rotate` in the [audit log](audit.md).

## CRL

A CRL (certificate revocation list) tells clients which certificates to distrust. A Built-in CA with **Publish CRL** on serves them to anyone, without sign-in:

- `GET /crl/{caId}.crl` is the current issuer's list.
- `GET /crl/{caId}/{issuerSerial}.crl` is the list of any issuer the CA has held, by lower-case hex serial.

Each list is valid for 7 days and sent with `Cache-Control: max-age=600`. The server answers 404 for an unknown CA, a CA without a CRL and an unknown serial alike. Every leaf points at its own issuer's list.

The CA detail shows the current list as a copyable **CRL URL**. If it shows **CRL off**, **Publish CRL** is disabled. If it says to set the base URL, open **Settings → General** and set **Base URL**: the URL cannot be built without it, and leaves issued before it was set carry no distribution point. Each retired issuer is a chip (first 8 characters of its serial and an "until" date); select it to copy that issuer's CRL URL (disabled when there is none). **Revoked** counts revocations on the CA.

## Revocation

Revoke a leaf when its key is lost or compromised. See [Revoke a version](certificates.md#revoke-a-version) for the steps. What happens depends on the CA:

- **Built-in CA**: the leaf is added to the CRL of the issuer that signed it (current or retired) and the very next CRL build lists it. The reason you choose is stored in the entry.
- **Vault PKI**: CertForge asks Vault to revoke the serial. Vault owns the revocation list; CertForge publishes no CRL for this kind. If Vault revoked it but CertForge could not record that, the request reports it; repeat the revoke to record it.
- **ACME**: not supported here.

Revoking a version that is already revoked is refused. Revoking a certificate's current version makes it renew immediately.

## Trust

Clients must trust the CA's root to accept its certificates. On a Built-in or Vault PKI CA's detail, **Trust bundle → Download** saves the CA certificate as `<name>-ca.pem`. For a generated Built-in CA it is the root and never changes on rotation. For an imported CA it is the last certificate of the chain you provided. For Vault PKI it is the CA certificate CertForge read from Vault when you created the CA. Install it in the trust store of every client that must trust your certificates.

The detail shows **Issuing certificate** with a validity bar and expiry, **Subject**, **Key type** and **Max leaf days** for a Built-in CA, and **Mount**, **Role** and **TTL** for Vault PKI.

## Vault PKI

A **Vault PKI** CA signs leaves through a PKI secrets engine in Vault or OpenBao.

1. Configure the Vault connection in **Settings → Integrations → Vault** first ([Vault](vault.md)). The form links there if it is missing.
2. On **CAs**, select **Add CA** and set **Type** to **Vault PKI**.
3. Enter a **Name**, the **Mount** (default `pki`) and the **Role** to sign against.
4. Optionally set **TTL**, a duration from `1h` to `19800h` for issued leaves. Left empty, CertForge sends none and Vault applies its role's own TTL; Vault's ceiling still applies.
5. Select **Save CA**.

CertForge reads the CA certificate from Vault at creation, so Vault must be reachable.

## Options

| Field | What it does | Default |
|---|---|---|
| **Type** | **ACME**, **Built-in CA** or **Vault PKI**. Fixed after creation. | **ACME** |
| **Preset** / **Directory URL** | ACME directory to use. | none |
| **Trust bundle** | PEM roots for a private ACME server (**Custom directory**). | none |
| **Resolvers** | DNS servers for propagation checks on this CA. | system resolvers |
| **Max leaf validity (days)** | Longest leaf this Built-in CA signs. Editable. | 397 (1 to 825) |
| **Publish CRL** | Serve the CRL. Editable. | on |
| **Mount** / **Role** / **TTL** | Vault PKI settings. | `pki` / none / Vault's |

## Common problems

**Saving a CA fails with a URL error.** The directory host does not resolve, or it is a loopback or metadata address. Use a resolvable name.

**Issuing fails because no account is set.** An ACME CA needs an account. Register one on that CA, then pick it in the defaults or the certificate's **Options**.

**Rotate is disabled.** The CA is imported (no root key) or you lack `cas:write`.

**Revoke is missing on a version.** Only versions CertForge issued from a private CA can be revoked.

**CRL shows "Set the base URL".** Set **Base URL** in **Settings → General**.

**Vault PKI save fails.** Vault is not configured or unreachable, or the mount or role is wrong. Check [Vault](vault.md).

## See also

- [Certificates](certificates.md), [Challenges](challenges.md), [Vault](vault.md)
- [Settings](settings.md)
