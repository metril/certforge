package issuance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/signer/adcs"
)

// adcsConfig is an adcs CA's public cas.config column: the Shared contract's
// AdcsConfig fields minus the write-only password (which lives sealed in
// secret_cfg). TemplateOID is read-only: set from the policy at create (and
// when the policy is re-read on update).
type adcsConfig struct {
	CEPURL         string `json:"cepUrl"`
	CESURL         string `json:"cesUrl,omitempty"`
	Template       string `json:"template"`
	Username       string `json:"username"`
	CABundlePEM    string `json:"caBundlePem,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	TemplateOID    string `json:"templateOid,omitempty"`
	// TemplateKeyTypes is read-only like TemplateOID: the key types the
	// template accepts, refreshed whenever the policy is re-read.
	TemplateKeyTypes []string `json:"templateKeyTypes,omitempty"`
}

// adcsSecretCfg is an adcs CA's sealed secret_cfg.
type adcsSecretCfg struct {
	Password string `json:"password"`
}

// adcsConfigWire is AdcsConfig's wire shape with every field optional, so
// parseADCSInput can tell "omitted" (default applies) from an explicit zero.
type adcsConfigWire struct {
	CEPURL         *string `json:"cepUrl"`
	CESURL         *string `json:"cesUrl"`
	Template       *string `json:"template"`
	Username       *string `json:"username"`
	CABundlePEM    *string `json:"caBundlePem"`
	TimeoutSeconds *int    `json:"timeoutSeconds"`
}

func parseADCSInput(raw map[string]any) (adcsConfig, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return adcsConfig{}, err
	}
	var w adcsConfigWire
	if err := json.Unmarshal(b, &w); err != nil {
		return adcsConfig{}, &ValidationError{"config", "invalid adcs config: " + err.Error()}
	}
	cfg := adcsConfig{TimeoutSeconds: 30}
	str := func(dst *string, src *string) {
		if src != nil {
			*dst = strings.TrimSpace(*src)
		}
	}
	str(&cfg.CEPURL, w.CEPURL)
	str(&cfg.CESURL, w.CESURL)
	str(&cfg.Template, w.Template)
	str(&cfg.Username, w.Username)
	if w.CABundlePEM != nil {
		ca, err := httpx.NormalizeCABundle(*w.CABundlePEM)
		if err != nil {
			return adcsConfig{}, &ValidationError{"config.caBundlePem", err.Error()}
		}
		cfg.CABundlePEM = ca
	}
	if w.TimeoutSeconds != nil {
		cfg.TimeoutSeconds = *w.TimeoutSeconds
	}
	return cfg, nil
}

func httpsURL(field, v string, required bool) error {
	if v == "" {
		if required {
			return &ValidationError{field, "required"}
		}
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return &ValidationError{field, "must be an https:// URL"}
	}
	return nil
}

// validate checks cfg's shape (Shared contract AdcsConfig bounds).
func (cfg adcsConfig) validate() error {
	if err := httpsURL("config.cepUrl", cfg.CEPURL, true); err != nil {
		return err
	}
	if err := httpsURL("config.cesUrl", cfg.CESURL, false); err != nil {
		return err
	}
	if cfg.Template == "" {
		return &ValidationError{"config.template", "required"}
	}
	if cfg.Username == "" {
		return &ValidationError{"config.username", "required"}
	}
	if cfg.TimeoutSeconds < 5 || cfg.TimeoutSeconds > 300 {
		return &ValidationError{"config.timeoutSeconds", "must be between 5 and 300"}
	}
	return nil
}

// SetADCSLoopback wires the policy for whether an AD CS web service may be
// reached on a loopback host (the notifications allowLoopbackUrls setting).
// Left unset, loopback is refused.
func (s *Store) SetADCSLoopback(f func(ctx context.Context) bool) { s.adcsLoopback = f }

func (s *Store) adcsClient(ctx context.Context, cfg adcsConfig) (*httpx.Client, error) {
	allow := s.adcsLoopback != nil && s.adcsLoopback(ctx)
	return httpx.New(httpx.Options{CAPEM: cfg.CABundlePEM, AllowLoopback: allow,
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, MaxBody: adcs.MaxBody})
}

func adcsSignerConfig(cfg adcsConfig, extraBundle string) adcs.Config {
	bundle := cfg.CABundlePEM
	if extraBundle != "" {
		bundle += "\n" + extraBundle
	}
	return adcs.Config{CEPURL: cfg.CEPURL, CESURL: cfg.CESURL, Template: cfg.Template, Username: cfg.Username,
		CABundlePEM: bundle, Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}
}

// adcsResolved is what reading the enrollment policy yields.
type adcsResolved struct {
	cfg                 adcsConfig
	trustPEM            string
	notBefore, notAfter time.Time
}

// adcsPolicies reads the enrollment policy with cfg and password. Failures
// are *ValidationError (bad bundle, authentication, unreachable CEP). The
// create/update path and the probe both go through it.
func (s *Store) adcsPolicies(ctx context.Context, cfg adcsConfig, password string) (*adcs.PolicyResult, error) {
	hc, err := s.adcsClient(ctx, cfg)
	if err != nil {
		return nil, &ValidationError{"config.caBundlePem", err.Error()}
	}
	sg := adcs.New(adcsSignerConfig(cfg, ""), password, hc)
	defer sg.Close()
	res, err := sg.Policies(ctx)
	if err != nil {
		if errors.Is(err, adcs.ErrAuth) {
			return nil, &ValidationError{"config.username", adcsAuthMessage(err)}
		}
		return nil, &ValidationError{"config.cepUrl", err.Error()}
	}
	return res, nil
}

// ADCSRequirement is one template requirement and whether the template meets
// it. Fix says, in AD CS console terms, how to change the template.
type ADCSRequirement struct {
	Key, Label, Fix string
	OK, Blocking    bool
}

// adcsRequirements judges t against what CertForge needs from a template.
func adcsRequirements(t *adcs.Template) []ADCSRequirement {
	reqs := []ADCSRequirement{
		{Key: "enroll", Label: "Service account can enroll", OK: t.CanEnroll, Blocking: true,
			Fix: "Security tab: give the service account Read and Enroll."},
		{Key: "approval", Label: "Issues without manager approval", OK: !t.RequiresApproval(), Blocking: true,
			Fix: "Issuance Requirements tab: clear \"CA certificate manager approval\"."},
		{Key: "signatures", Label: "Needs no authorized signatures", OK: t.RASignatures == 0, Blocking: true,
			Fix: "Issuance Requirements tab: set \"This number of authorized signatures\" to 0."},
		{Key: "subject", Label: "Subject supplied in the request", OK: t.SuppliesSubject(), Blocking: true,
			Fix: "Subject Name tab: select \"Supply in the request\"."},
		{Key: "serverAuth", Label: "Allows Server Authentication", OK: t.ServerAuthOK(),
			Fix: "Extensions tab, Application Policies: add Server Authentication."},
	}
	if t.KeyAlgorithm == "RSA" {
		reqs = append(reqs, ADCSRequirement{Key: "keyAlgorithm", Label: "Allows elliptic-curve keys", OK: false,
			Fix: "To issue EC keys: Compatibility tab, choose Windows Server 2008 or later; Cryptography tab, set Provider Category to \"Key Storage Provider\" and Algorithm to \"ECDSA_P384\"."})
	}
	return reqs
}

// adcsBlockReasons maps a blocking requirement to its create/update error.
var adcsBlockReasons = map[string]string{
	"enroll":     "the service account lacks Enroll permission on this template",
	"approval":   "template requires CA manager approval; use a template that issues automatically",
	"signatures": "template requires authorized signatures; set the number to 0",
	"subject":    "template does not let the request supply the subject; select \"Supply in the request\"",
}

// usableADCSTemplate returns the named template, or a *ValidationError saying
// why it cannot be used: the first failing blocking requirement.
func usableADCSTemplate(res *adcs.PolicyResult, name string) (*adcs.Template, error) {
	tpl, err := res.Template(name)
	if err != nil {
		return nil, &ValidationError{"config.template", err.Error()}
	}
	for _, r := range adcsRequirements(tpl) {
		if r.Blocking && !r.OK {
			return nil, &ValidationError{"config.template", adcsBlockReasons[r.Key]}
		}
	}
	return tpl, nil
}

// ADCSProbeInput is a probe of an AD CS enrollment policy service.
type ADCSProbeInput struct {
	Config   map[string]any // AdcsConfig fields; template is optional
	Password string         // challenge.Unchanged with CAID reuses the saved CA's password
	CAID     *uuid.UUID
}

// ADCSProbeTemplate is one published template.
type ADCSProbeTemplate struct {
	Name, OID                string
	MinKeySize               int
	CanEnroll, NeedsApproval bool
	Requirements             []ADCSRequirement
	AllowedKeyTypes          []string
	KeyAlgorithm             string
	Schema                   int
	LegacyCSP                bool
}

// ADCSProbeSelected is the verdict on the template named in the probe.
type ADCSProbeSelected struct {
	Name, Reason string
	Usable       bool
}

// ADCSProbeResult is a probe outcome. Error is set (OK false) when the
// service could not be read; Templates and Selected are empty then.
type ADCSProbeResult struct {
	OK        bool
	Error     string
	Templates []ADCSProbeTemplate
	Selected  *ADCSProbeSelected
}

// ProbeADCS reads the policy with the supplied settings and lists the
// templates, judging cfg.template by the same rules as create/update. Input
// errors are *ValidationError or ErrNotFound; a failing service yields
// OK false, not an error.
func (s *Store) ProbeADCS(ctx context.Context, orgID uuid.UUID, in ADCSProbeInput) (ADCSProbeResult, error) {
	cfg, err := parseADCSInput(in.Config)
	if err != nil {
		return ADCSProbeResult{}, err
	}
	if err := httpsURL("config.cepUrl", cfg.CEPURL, true); err != nil {
		return ADCSProbeResult{}, err
	}
	if err := httpsURL("config.cesUrl", cfg.CESURL, false); err != nil {
		return ADCSProbeResult{}, err
	}
	if cfg.Username == "" {
		return ADCSProbeResult{}, &ValidationError{"config.username", "required"}
	}
	if cfg.TimeoutSeconds < 5 || cfg.TimeoutSeconds > 300 {
		return ADCSProbeResult{}, &ValidationError{"config.timeoutSeconds", "must be between 5 and 300"}
	}
	pw := in.Password
	if pw == challenge.Unchanged {
		if in.CAID == nil {
			return ADCSProbeResult{}, &ValidationError{"config.password", "value is only valid with a saved CA (caId)"}
		}
		row, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: *in.CAID, OrgID: orgID})
		if err != nil {
			return ADCSProbeResult{}, notFound(err)
		}
		if row.Type != CATypeADCS {
			return ADCSProbeResult{}, &ValidationError{"caId", "not an adcs CA"}
		}
		var sec adcsSecretCfg
		if err := s.openJSON(ctx, row.SecretCfg, &sec); err != nil {
			return ADCSProbeResult{}, err
		}
		var old adcsConfig
		if err := json.Unmarshal(row.Config, &old); err != nil {
			return ADCSProbeResult{}, err
		}
		if adcsConnectionChanged(old, cfg) {
			return ADCSProbeResult{}, errADCSReenterPassword
		}
		pw = sec.Password
	}
	if pw == "" {
		return ADCSProbeResult{}, &ValidationError{"config.password", "required"}
	}
	res, err := s.adcsPolicies(ctx, cfg, pw)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) && ve.Field != "config.caBundlePem" {
			return ADCSProbeResult{Error: ve.Msg}, nil
		}
		return ADCSProbeResult{}, err
	}
	out := ADCSProbeResult{OK: true, Templates: make([]ADCSProbeTemplate, 0, len(res.Templates))}
	for _, t := range res.Templates {
		out.Templates = append(out.Templates, ADCSProbeTemplate{Name: t.Name, OID: t.OID, MinKeySize: t.MinKeySize,
			CanEnroll: t.CanEnroll, NeedsApproval: t.RequiresApproval(), Requirements: adcsRequirements(&t),
			AllowedKeyTypes: t.AllowedKeyTypes(), KeyAlgorithm: t.KeyAlgorithm, Schema: t.Schema, LegacyCSP: t.LegacyCSP()})
	}
	if cfg.Template != "" {
		sel := &ADCSProbeSelected{Name: cfg.Template, Usable: true}
		if tpl, err := usableADCSTemplate(res, cfg.Template); err != nil {
			sel.Usable = false
			var ve *ValidationError
			if errors.As(err, &ve) {
				sel.Reason = ve.Msg
			}
		} else {
			sel.Name = tpl.Name
		}
		out.Selected = sel
	}
	return out, nil
}

// resolveADCS runs GetPolicies with cfg and password, requires the template
// to exist, fills in cfg.CESURL (when empty) and cfg.TemplateOID, and returns
// the issuing CA certificate(s) as a PEM trust bundle with the first one's
// validity window.
func (s *Store) resolveADCS(ctx context.Context, cfg adcsConfig, password string) (adcsResolved, error) {
	res, err := s.adcsPolicies(ctx, cfg, password)
	if err != nil {
		return adcsResolved{}, err
	}
	tpl, err := usableADCSTemplate(res, cfg.Template)
	if err != nil {
		return adcsResolved{}, err
	}
	out := adcsResolved{cfg: cfg}
	out.cfg.TemplateOID = tpl.OID
	out.cfg.TemplateKeyTypes = tpl.AllowedKeyTypes()
	for _, ca := range tpl.CAs {
		if out.cfg.CESURL == "" && len(ca.CESURLs) > 0 {
			out.cfg.CESURL = ca.CESURLs[0]
		}
		for _, c := range ca.Certs {
			if out.trustPEM == "" {
				out.notBefore, out.notAfter = c.NotBefore, c.NotAfter
			}
			out.trustPEM += pemEncodeCert(c)
		}
	}
	if out.cfg.CESURL == "" {
		return adcsResolved{}, &ValidationError{"config.cesUrl", "the policy publishes no username/password enrollment URL for this template; set it explicitly"}
	}
	if out.trustPEM == "" {
		return adcsResolved{}, &ValidationError{"config.cepUrl", "the policy publishes no CA certificate for this template"}
	}
	return out, nil
}

// createADCSCA validates the config, reads the enrollment policy with the
// supplied credentials (the template must exist), and stores the CA: the CA
// certificate(s) become trust_bundle_pem, the first one's validity the
// not_before/not_after, and the password is sealed into secret_cfg.
func (s *Store) createADCSCA(ctx context.Context, orgID uuid.UUID, in CAInput) (CA, error) {
	cfg, err := parseADCSInput(in.Config)
	if err != nil {
		return CA{}, err
	}
	if err := cfg.validate(); err != nil {
		return CA{}, err
	}
	pw := ""
	if in.ADCSPassword != nil {
		pw = *in.ADCSPassword
	}
	if pw == challenge.Unchanged {
		return CA{}, &ValidationError{Field: "config.password", Msg: "value is only valid when updating a stored secret"}
	}
	if pw == "" {
		return CA{}, &ValidationError{"config.password", "required"}
	}
	r, err := s.resolveADCS(ctx, cfg, pw)
	if err != nil {
		return CA{}, err
	}
	cfgRaw, err := json.Marshal(r.cfg)
	if err != nil {
		return CA{}, err
	}
	sealed, err := s.sealJSON(ctx, adcsSecretCfg{Password: pw})
	if err != nil {
		return CA{}, err
	}
	row, err := s.q.CreateCA(ctx, sqlcgen.CreateCAParams{OrgID: orgID, Name: in.Name, Type: in.Type, Config: cfgRaw,
		SecretCfg: sealed, NotBefore: &r.notBefore, NotAfter: &r.notAfter, Preset: "", DirectoryUrl: "",
		TrustBundlePem: r.trustPEM, EabKid: "", EabHmac: nil, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row)
}

var errADCSReenterPassword = &ValidationError{"config.password", "must be re-entered when the endpoint, account or TLS bundle change"}

// adcsConnectionChanged reports whether cfg points the stored password at a
// different connection than old (endpoints, account or TLS bundle). A saved
// password must not follow such a change; the template alone may change. An
// empty CES URL means "derive it from the policy", so it is not a change.
func adcsConnectionChanged(old, cfg adcsConfig) bool {
	return cfg.CEPURL != old.CEPURL || (cfg.CESURL != "" && cfg.CESURL != old.CESURL) ||
		cfg.Username != old.Username || cfg.CABundlePEM != old.CABundlePEM
}

// adcsUpdateHook, when set by a test, runs between updateADCSCA's unlocked
// read and its row lock, to simulate a concurrent writer.
var adcsUpdateHook func()

// updateADCSCA replaces an adcs CA's editable fields. A nil or
// challenge.Unchanged password keeps the stored one; a changed endpoint,
// template, account, password or TLS bundle re-reads the enrollment policy
// (refreshing the template OID, CES URL, trust bundle and validity window).
func (s *Store) updateADCSCA(ctx context.Context, orgID, id uuid.UUID, in CAInput) (CA, error) {
	cfg, err := parseADCSInput(in.Config)
	if err != nil {
		return CA{}, err
	}
	if err := cfg.validate(); err != nil {
		return CA{}, err
	}
	cur, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, notFound(err)
	}
	var old adcsConfig
	if err := json.Unmarshal(cur.Config, &old); err != nil {
		return CA{}, err
	}
	var storedSec adcsSecretCfg
	if err := s.openJSON(ctx, cur.SecretCfg, &storedSec); err != nil {
		return CA{}, err
	}
	pw, newPW := storedSec.Password, false
	if in.ADCSPassword != nil && *in.ADCSPassword != challenge.Unchanged {
		if *in.ADCSPassword == "" {
			return CA{}, &ValidationError{"config.password", "must not be empty"}
		}
		pw, newPW = *in.ADCSPassword, true
	}
	if !newPW && adcsConnectionChanged(old, cfg) {
		return CA{}, errADCSReenterPassword
	}
	var (
		resolved bool
		trust    string
		nb, na   *time.Time
	)
	if newPW || cfg.CEPURL != old.CEPURL || cfg.CESURL != old.CESURL || cfg.Template != old.Template ||
		cfg.Username != old.Username || cfg.CABundlePEM != old.CABundlePEM {
		r, err := s.resolveADCS(ctx, cfg, pw)
		if err != nil {
			return CA{}, err
		}
		cfg, trust, nb, na = r.cfg, r.trustPEM, &r.notBefore, &r.notAfter
		resolved = true
	}
	var newSecret []byte
	if newPW {
		if newSecret, err = s.sealJSON(ctx, adcsSecretCfg{Password: pw}); err != nil {
			return CA{}, err
		}
	}
	if adcsUpdateHook != nil {
		adcsUpdateHook()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CA{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	locked, err := q.LockCA(ctx, sqlcgen.LockCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, notFound(err)
	}
	// Everything not freshly resolved or sealed comes from the locked row,
	// never from cur (read before the lock): a concurrent rewrap of
	// secret_cfg must not be overwritten with a stale blob.
	secret := locked.SecretCfg
	if newPW {
		secret = newSecret
	}
	if !resolved {
		var lockedCfg adcsConfig
		if err := json.Unmarshal(locked.Config, &lockedCfg); err != nil {
			return CA{}, err
		}
		cfg.TemplateOID, cfg.TemplateKeyTypes = lockedCfg.TemplateOID, lockedCfg.TemplateKeyTypes
		trust, nb, na = locked.TrustBundlePem, locked.NotBefore, locked.NotAfter
	}
	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		return CA{}, err
	}
	if _, err := q.UpdateCA(ctx, sqlcgen.UpdateCAParams{ID: id, OrgID: orgID, Name: in.Name, Type: in.Type, Config: cfgRaw,
		Preset: "", DirectoryUrl: "", TrustBundlePem: trust, EabKid: "", EabHmac: nil, Resolvers: in.Resolvers}); err != nil {
		return CA{}, dbErr(err, "name")
	}
	row, err := q.UpdateCACrypto(ctx, sqlcgen.UpdateCACryptoParams{ID: id, OrgID: orgID, Config: cfgRaw, SecretCfg: secret,
		NotBefore: nb, NotAfter: na, CrlNumber: locked.CrlNumber})
	if err != nil {
		return CA{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CA{}, err
	}
	return caFromRow(row)
}

// adcsSigner builds the adcs Signer for ca, opening its sealed password.
func (s *Store) adcsSigner(ctx context.Context, ca CA) (signer.Signer, error) {
	row, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: ca.ID, OrgID: ca.OrgID})
	if err != nil {
		return nil, notFound(err)
	}
	var cfg adcsConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, err
	}
	var sec adcsSecretCfg
	if err := s.openJSON(ctx, row.SecretCfg, &sec); err != nil {
		return nil, fmt.Errorf("open adcs secret: %w", err)
	}
	hc, err := s.adcsClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return adcs.New(adcsSignerConfig(cfg, row.TrustBundlePem), sec.Password, hc), nil
}

// adcsAuthMessage is the user-facing text for an AD CS authentication
// failure: a friendly lead plus the server's reason and, for a username
// without DOMAIN\ or @domain, the format hint. It never includes the password.
func adcsAuthMessage(err error) string {
	const lead = "authentication to the enrollment policy service failed"
	var ae *adcs.AuthError
	if errors.As(err, &ae) {
		return ae.Message(lead)
	}
	return lead
}
