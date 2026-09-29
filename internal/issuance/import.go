package issuance

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/importer"
	"github.com/metril/certforge/internal/signer"
)

// ImportResult is the outcome of ImportCertificates, or a preview when
// DryRun is true.
type ImportResult struct {
	DryRun bool
	Items  []ImportItem
}

// ImportItem is what ImportCertificates did, or would do in dry-run mode,
// with one certificate found in an import archive.
type ImportItem struct {
	Name          string
	Names         []string // common name followed by SANs
	NotAfter      time.Time
	Issuer        string
	HasKey        bool
	Source        string // "acmesh" or "certbot"
	Action        string // "create" or "skip"
	Reason        string
	CertificateID *uuid.UUID // set when Action is "create" and DryRun is false
}

// defaultImporters is the layouts ImportCertificates tries, in order; the
// first whose Detect reports true wins — an archive is either an acme.sh
// or a certbot tree, never both at once. Service.Importers overrides this
// for tests.
var defaultImporters = []importer.Importer{importer.AcmeSh, importer.Certbot}

// importers returns s.Importers, or defaultImporters when unset.
func (s *Service) importers() []importer.Importer {
	if s.Importers != nil {
		return s.Importers
	}
	return defaultImporters
}

// importOverrides resolves what ImportCertificates writes into every
// certificate it creates: caId always, and accountId only when the org's
// own effective default account does not already belong to caID — a plain
// org already pointed at this CA needs no override at all, so it keeps
// tracking whatever account the org default points to later. Also returns
// the effective renew policy NextRenewAt applies to each imported
// version's own validity. A 422 on caId means no account in this org is
// registered against caID at all.
func (s *Service) importOverrides(ctx context.Context, orgID, caID uuid.UUID) (Defaults, RenewPolicy, error) {
	eff, err := s.Store.EffectiveOrg(ctx, orgID)
	if err != nil {
		return Defaults{}, RenewPolicy{}, err
	}
	over := Defaults{CAID: &caID}
	if eff.AccountID.Value != nil {
		if acct, aerr := s.Store.GetAccount(ctx, orgID, *eff.AccountID.Value); aerr == nil && acct.CAID == caID {
			return over, eff.RenewPolicy.Value, nil
		}
	}
	accounts, err := s.Store.ListAccounts(ctx, orgID)
	if err != nil {
		return Defaults{}, RenewPolicy{}, err
	}
	for _, a := range accounts {
		if a.CAID == caID {
			id := a.ID
			over.AccountID = &id
			return over, eff.RenewPolicy.Value, nil
		}
	}
	return Defaults{}, RenewPolicy{}, &ValidationError{"caId", "no ACME account for this CA"}
}

// ImportCertificates previews (dryRun) or stores every certificate found in
// fsys (an acme.sh or certbot tree, typically importer.ExtractArchive's own
// result) as a managed certificate renewed from now on against caID. The
// dry-run and create paths share importOne's single code path exactly
// (rolling the transaction back instead of committing it), so a preview
// can never claim something would succeed that create would in fact
// refuse — including a name collision against an already-stored
// certificate, caught the same way either mode finds out about it: the
// unique (org_id, name) constraint itself. A collision between two entries
// of the *same* archive (acme.sh's <domain>/ and <domain>_ecc/ both name
// themselves <domain>) is different: each entry's transaction commits or
// rolls back on its own, so the second one would never actually observe
// the first's uncommitted-then-rolled-back row in dry-run mode — this
// loop tracks names claimed within the run itself (claimed), in memory,
// so dry-run and create report the exact same second entry as a skipped
// duplicate, not "would create".
func (s *Service) ImportCertificates(ctx context.Context, orgID, caID uuid.UUID, fsys fs.FS, dryRun bool) (ImportResult, error) {
	if _, err := s.Store.GetCA(ctx, orgID, caID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ImportResult{}, &ValidationError{"caId", "no such CA in this org"}
		}
		return ImportResult{}, err
	}
	over, policy, err := s.importOverrides(ctx, orgID, caID)
	if err != nil {
		return ImportResult{}, err
	}

	var found []importer.ImportedCert
	for _, imp := range s.importers() {
		if !imp.Detect(fsys) {
			continue
		}
		if found, err = imp.Import(ctx, fsys); err != nil {
			return ImportResult{}, err
		}
		break
	}

	result := ImportResult{DryRun: dryRun}
	claimed := map[string]bool{}
	var created, skipped []string
	for _, ic := range found {
		name := strings.TrimSpace(ic.Name)
		var item ImportItem
		if name != "" && claimed[name] {
			item = ImportItem{Name: name, Names: []string{}, Source: string(ic.Source), HasKey: len(ic.KeyPKCS8) > 0,
				Action: "skip", Reason: "duplicate name in archive"}
		} else {
			item, err = s.importOne(ctx, orgID, over, policy, ic, dryRun)
			if err != nil {
				return ImportResult{}, err
			}
			if item.Action == "create" {
				claimed[name] = true
			}
		}
		result.Items = append(result.Items, item)
		if item.Action == "create" {
			created = append(created, item.Name)
		} else {
			skipped = append(skipped, item.Name)
		}
	}
	if !dryRun && len(created) > 0 {
		s.auditImport(ctx, orgID, len(created), len(skipped), created)
	}
	return result, nil
}

// maxImportNameLen mirrors the 1–100 length rule every other named
// resource's own DB CHECK constraint enforces (clients, sites, api keys, ...);
// certificates.name has no such constraint (Task 13's upload never needed
// one — a caller chooses that name deliberately), but an imported name is
// derived from an archive entry, so it needs the same defensive bound
// applied here instead.
const maxImportNameLen = 100

// importOne runs CreateExternalCertificate, certstore.Insert and
// SetCurrentVersion inside one transaction for a single archive entry,
// exactly as UploadCertificate does for an uploaded one, then either
// commits (create mode) or rolls back (dry-run mode). Every business-level
// reason to skip this entry (an invalid name, an unparseable leaf, a chain
// that does not lead back to the leaf, a leaf key type CertForge does not
// support, a key that does not match the leaf, or a name already taken by
// another certificate in this org) reports as ImportItem{Action: "skip"}
// rather than failing the whole request; only an infrastructure error (the
// database itself, or caID/accountId having gone missing from under this
// request — see the validateDefaultsTx call below) is returned.
func (s *Service) importOne(ctx context.Context, orgID uuid.UUID, over Defaults, policy RenewPolicy, ic importer.ImportedCert, dryRun bool) (ImportItem, error) {
	item := ImportItem{Name: strings.TrimSpace(ic.Name), Names: []string{}, Source: string(ic.Source), HasKey: len(ic.KeyPKCS8) > 0}
	skip := func(reason string) (ImportItem, error) {
		item.Action, item.Reason = "skip", reason
		return item, nil
	}
	if item.Name == "" || len(item.Name) > maxImportNameLen {
		return skip("invalid name")
	}
	leaf, err := x509.ParseCertificate(ic.LeafDER)
	if err != nil {
		return skip("cannot parse leaf: " + err.Error())
	}
	item.NotAfter, item.Issuer = leaf.NotAfter, leaf.Issuer.CommonName
	chainDER, err := validateChain(leaf, ic.ChainDER, "chain")
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return skip(ve.Msg)
		}
		return ImportItem{}, err
	}
	cn, sans, err := uploadNames(leaf)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return skip(ve.Msg)
		}
		return ImportItem{}, err
	}
	item.Names = append([]string{cn}, sans...)
	keyType, err := signer.KeyTypeOf(leaf.PublicKey)
	if err != nil {
		return skip(err.Error())
	}
	// A key was found alongside the certificate: it must actually be this
	// leaf's key, the same check ParseUpload (upload.go) applies to an
	// uploaded key — otherwise an imported certificate would silently seal
	// and store a key that can never terminate TLS for it.
	if len(ic.KeyPKCS8) > 0 {
		key, kerr := x509.ParsePKCS8PrivateKey(ic.KeyPKCS8)
		if kerr != nil {
			return skip("cannot parse key: " + kerr.Error())
		}
		signerKey, ok := key.(crypto.Signer)
		if !ok {
			return skip(fmt.Sprintf("unsupported key type %T", key))
		}
		if !publicKeysEqual(leaf.PublicKey, signerKey.Public()) {
			return skip("key does not match the certificate")
		}
	}
	status := StatusActive
	now := time.Now()
	if !leaf.NotAfter.After(now) {
		status = StatusExpired
	}
	nextRenew := NextRenewAt(policy, leaf.NotBefore, leaf.NotAfter, now)

	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return ImportItem{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// over.CAID (and over.AccountID, when set) are about to go into this
	// certificate's overrides jsonb; validateDefaultsTx both re-checks they
	// still name a row of this org and takes the FOR KEY SHARE lock P34
	// requires for any id held in jsonb, so a concurrent DeleteCA/
	// DeleteAccount (FOR UPDATE on the same row) blocks until this
	// transaction ends instead of racing this write into a dangling
	// reference — the same guarantee prepareCertTx gives an ordinary
	// CreateCertificate. Unlike a business-level skip, this failing means
	// caID itself has gone missing from under the whole request, so it
	// propagates as a real error rather than skipping just this one item.
	// aboveCAID nil: an imported/uploaded certificate is unmanaged (never
	// issued or renewed by CertForge), so the write-time accountId-vs-
	// inherited-CA check batch-4 added for prepareCertTx does not apply
	// here — over.CAID/AccountID, when set at all, are still checked
	// against each other (the existing same-level check below).
	if err := s.Store.validateDefaultsTx(ctx, s.Store.q.WithTx(tx), orgID, over, nil, false, nil); err != nil {
		return ImportItem{}, err
	}

	c, err := s.Store.CreateExternalCertificate(ctx, tx, orgID, item.Name, cn, sans, over, true, status, &nextRenew)
	if err != nil {
		var ce *ConflictError
		if errors.As(err, &ce) {
			return skip("a certificate named \"" + item.Name + "\" already exists")
		}
		return ImportItem{}, err
	}
	iss := &signer.Issued{LeafDER: ic.LeafDER, ChainDER: chainDER, PrivateKeyPKCS8: ic.KeyPKCS8,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Serial: leaf.SerialNumber.Text(16)}
	v, err := s.Certs.Insert(ctx, tx, c.ID, iss, string(keyType), certstore.InsertOpts{Source: "imported"})
	if err != nil {
		return ImportItem{}, err
	}
	c, err = s.Store.SetCurrentVersion(ctx, tx, c.ID, v.ID, cn, sans, status, &nextRenew)
	if err != nil {
		return ImportItem{}, err
	}
	if dryRun {
		item.Action, item.Reason = "create", "would be created"
		return item, nil // rolled back by the deferred Rollback above
	}
	if err := tx.Commit(ctx); err != nil {
		return ImportItem{}, err
	}
	item.Action, item.Reason = "create", "created"
	id := c.ID
	item.CertificateID = &id
	return item, nil
}

// auditImport records one certificate.import event per request that
// created anything: counts and the names actually created, never
// certificate material. names of entries that were skipped are not
// recorded here (they were not imported); a caller wanting the full
// picture has ImportResult.Items.
func (s *Service) auditImport(ctx context.Context, orgID uuid.UUID, created, skipped int, names []string) {
	if s.Auditor == nil {
		return
	}
	event := audit.Event{Action: "certificate.import", ResourceType: "certificate", OrgID: &orgID,
		Details: map[string]any{"created": created, "skipped": skipped, "names": names}}
	if err := s.Auditor.Record(ctx, event); err != nil {
		s.logger().Error("audit record failed", "action", event.Action, "err", err)
	}
}
