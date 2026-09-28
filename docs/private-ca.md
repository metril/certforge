# Private CA

`internal/signer/localca` is CertForge's built-in private certificate
authority: pure certificate generation, import, rotation and CRL logic with
no I/O of its own. It backs CAs of kind `localca` (see `docs/api.md`'s CA
schema); the CA lifecycle, persistence and public CRL routes are wired
separately (`internal/issuance`, Phase 5A Task 7).

## Model {#model}

A `localca` CA is two certificates:

- **Root** — a self-signed CA, `KeyUsageCertSign | KeyUsageCRLSign`, path
  length 1 (it may sign at most one layer of intermediate below it). Its
  private key is sealed and used only to sign a new issuing intermediate
  (`Rotate`); day-to-day issuance never touches it.
- **Issuing intermediate** — signed by the root, `MaxPathLenZero` (it may
  not sign further CAs), also `KeyUsageCertSign | KeyUsageCRLSign`. Its
  private key signs every leaf certificate and every CRL. Its common name
  is the subject's with a suffix identifying when it was minted, e.g.
  `Acme Corp Issuing CA 2026-01`.

Both certificates get a `SubjectKeyId` (RFC 5280 §4.2.1.2 method 1) and the
intermediate's `AuthorityKeyId` is the root's `SubjectKeyId` — Go's
`x509.CreateCertificate` does this automatically for CA templates.

A leaf's `NotAfter` is `min(now + maxLeafDays, issuing.NotAfter)`: a leaf
can never outlive the issuing certificate that signed it. Leaves carry
`serverAuth` and `clientAuth` EKUs and, when the server's base URL is
configured, a CRL distribution point pointing at that issuing certificate's
CRL (`<baseUrl>/crl/<caId>/<issuerSerial>.crl`).

## Import {#import}

An operator can bring their own issuing certificate instead of generating
one: `Import(certPEM, keyPEM, crl, now)` takes a PEM bundle (the issuing
certificate first, then its chain in order) and the issuing certificate's
private key (PKCS#1, SEC1 or PKCS#8).

Requirements:

- The issuing certificate must be a CA (`IsCA`, `KeyUsageCertSign`) and
  currently valid.
- The supplied private key must match the issuing certificate's public key.
- When `crl` is requested, the issuing certificate must itself be able to
  sign one: `KeyUsageCRLSign` set and a `SubjectKeyId` present. Otherwise
  `Import` returns `ErrCannotSignCRL` (the CA lifecycle layer maps this to
  a 422 "issuing certificate cannot sign CRLs").

Trust is the last certificate in the chain when it is self-signed (the
imported root); otherwise there is no local root and trust is the top of
the supplied chain as-is. An import never needs a root private key —
`Rotate` is only available for a generated root whose key was kept.

## Rotation {#rotation}

`Rotate(root, rootKeyPKCS8, cfg, now)` signs a fresh issuing intermediate
under the existing root and returns new `Material`; the caller persists it
as the CA's current issuer and keeps the retired one (and its sealed key)
around until its own `NotAfter`, so certificates it already issued can
still be revoked and its CRL can still be served. `Rotate` zeroes its copy
of `rootKeyPKCS8` once the key is parsed — the root key should not outlive
the single rotation call that needed it.

Leaves issued under a retired intermediate keep verifying against it
unchanged: rotation never touches previously issued certificates, only
which intermediate signs the next one.

## CRL {#crl}

`BuildCRL(issuer, key, revoked, number, now)` signs a CRL with
`x509.CreateRevocationList`: `ThisUpdate` is `now`, `NextUpdate` is
`now + 7 days`, and each entry carries its RFC 5280 §5.3.1 reason code.

Phase 5A Task 7 wires this to two public, unauthenticated routes on the
main listener (outside `/api/v1`, documented in `docs/api.md`, not the
OpenAPI document):

- `GET /crl/{caId}.crl` — the CA's current issuer.
- `GET /crl/{caId}/{issuerSerial}.crl` — any issuer the CA has held
  (current or retired), by lower-case hex serial.

Both serve `application/pkix-crl` DER with `Cache-Control: max-age=600`;
the server also caches the built DER in memory for up to 10 minutes.
Every issuer has its own CRL, numbered from the CA's single `crl_number`
counter (bumped on every revocation, regardless of which issuer signed the
revoked leaf) — a leaf's own CRL distribution point always names its
issuer's specific route. The route answers 404 for an unknown CA id, a
non-localca CA, `crl: false`, or an unknown issuer serial alike: a probing
client learns nothing from the response.

## Revocation {#revocation}

`POST /orgs/{orgId}/certificates/{id}/versions/{vid}/revoke` revokes one
issued leaf (private CAs only — 422 "not supported for ACME CAs yet" for a
version from an acme CA, and 422 for a version that was imported or
uploaded rather than issued by CertForge). The handler locks the
certificate version and its CA row, determines which issuer actually
signed the leaf (by `AuthorityKeyId`: the current issuer, or a retired one
still held from a rotation), and calls that issuer's `Signer.Revoke`,
which appends the leaf to the CA's revoked list and bumps `crl_number` —
so the very next CRL build already lists it. Revoking an
already-revoked version is 409.

## Trust {#trust}

A `localca` CA's `config` (public) and `secret_cfg` (sealed) columns
together hold everything the CA needs:

- `config`: the operator-chosen public fields (subject, key type, validity
  years, `maxLeafDays`, `crl`), plus the read-only `imported` flag, the
  current `issuingPem`, `retired[]` (each retired issuer's certificate,
  `notAfter` and serial, kept until its own expiry) and `revokedCount`.
- `secret_cfg`: the root key (generated CAs only — an imported CA has none,
  so it can never `rotate`), the current issuing key, each retired
  issuer's key, and (generated or imported) `importKeyPem` when the CA was
  created by import, kept only so `storedSecrets` can report it held.

`trustBundlePem` is the CA's trust anchor: the root's PEM for a generated
CA, or for an import the last certificate of the supplied `importPem`
chain (the issuing certificate itself when no chain was given, matching
`localca.Import`'s own rule for when there is no separate root to trust
through). It never changes across a `rotate` — only which certificate
signs new leaves changes.

The GET body for a `localca` CA never contains a private key: `secret_cfg`
is sealed and is never read by the CA's own JSON rendering, only by the
signer and CRL paths that actually need the key material.
