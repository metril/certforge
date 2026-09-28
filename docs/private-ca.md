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

## CRL

`BuildCRL(issuer, key, revoked, number, now)` signs a CRL with
`x509.CreateRevocationList`: `ThisUpdate` is `now`, `NextUpdate` is
`now + 7 days`, and each entry carries its RFC 5280 §5.3.1 reason code.
