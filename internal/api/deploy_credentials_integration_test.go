//go:build integration

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
	"github.com/metril/certforge/internal/targets/targetstest"
)

func (f *agentFixture) createCred(t *testing.T, name, kind string, cfg map[string]interface{}) gen.DeployCredential {
	t.Helper()
	res, err := f.srv.CreateDeployCredential(f.as("org-admin"), gen.CreateDeployCredentialRequestObject{OrgId: f.org,
		Body: &gen.DeployCredentialInput{Name: name, Kind: gen.DeployCredentialKind(kind), Config: cfg}})
	if err != nil {
		t.Fatal(err)
	}
	return gen.DeployCredential(res.(gen.CreateDeployCredential201JSONResponse))
}

func (f *agentFixture) createTargetWith(ctx context.Context, name string, runsOn gen.RunsOn, cfg map[string]interface{}, cred *uuid.UUID) (gen.DeployTarget, error) {
	res, err := f.srv.CreateDeployTarget(ctx, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: name, Type: "test-secret", RunsOn: &runsOn, Config: cfg, CredentialId: cred}})
	if err != nil {
		return gen.DeployTarget{}, err
	}
	return gen.DeployTarget(res.(gen.CreateDeployTarget201JSONResponse)), nil
}

func (f *agentFixture) updateTargetWith(ctx context.Context, tgt gen.DeployTarget, name string, cfg map[string]interface{}, cred *uuid.UUID) error {
	_, err := f.srv.UpdateDeployTarget(ctx, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: tgt.Id,
		Body: &gen.DeployTargetInput{Name: name, Type: tgt.Type, Config: cfg, CredentialId: cred}})
	return err
}

func TestDeployCredentialCRUDAndReveal(t *testing.T) {
	f := newAgentFixture(t)
	admin := f.as("org-admin")

	c := f.createCred(t, "tok", "token", map[string]interface{}{"token": "s3cret-value"})
	if c.Kind != "token" || c.StoredSecrets == nil || len(*c.StoredSecrets) != 1 || (*c.StoredSecrets)[0] != "token" {
		t.Fatalf("created = %+v", c)
	}
	if _, ok := c.Config["token"]; ok {
		t.Fatalf("config leaks the secret: %+v", c.Config)
	}

	// Operators and viewers cannot write; viewers can read.
	_, err := f.srv.CreateDeployCredential(f.as("operator"), gen.CreateDeployCredentialRequestObject{OrgId: f.org,
		Body: &gen.DeployCredentialInput{Name: "x", Kind: "token", Config: map[string]interface{}{"token": "x"}}})
	wantStatus(t, err, 403)
	res, err := f.srv.ListDeployCredentials(f.as("viewer"), gen.ListDeployCredentialsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if list := res.(gen.ListDeployCredentials200JSONResponse); len(list) != 1 || list[0].Id != c.Id {
		t.Fatalf("list = %+v", list)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), "s3cret-value") {
		t.Fatal("list leaks the secret")
	}

	// Invalid input.
	_, err = f.srv.CreateDeployCredential(admin, gen.CreateDeployCredentialRequestObject{OrgId: f.org,
		Body: &gen.DeployCredentialInput{Name: "bad", Kind: "nope", Config: map[string]interface{}{}}})
	wantStatus(t, err, 422)
	_, err = f.srv.CreateDeployCredential(admin, gen.CreateDeployCredentialRequestObject{OrgId: f.org,
		Body: &gen.DeployCredentialInput{Name: "bad", Kind: "token", Config: map[string]interface{}{}}})
	wantStatus(t, err, 422)
	_, err = f.srv.CreateDeployCredential(admin, gen.CreateDeployCredentialRequestObject{OrgId: f.org,
		Body: &gen.DeployCredentialInput{Name: "tok", Kind: "token", Config: map[string]interface{}{"token": "y"}}})
	wantStatus(t, err, 409)

	// __unchanged__ keeps the stored secret; a required secret left out is a 422.
	if _, err := f.srv.UpdateDeployCredential(admin, gen.UpdateDeployCredentialRequestObject{OrgId: f.org, Id: c.Id,
		Body: &gen.DeployCredentialUpdate{Name: "tok2", Config: map[string]interface{}{"token": "__unchanged__"}}}); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.UpdateDeployCredential(admin, gen.UpdateDeployCredentialRequestObject{OrgId: f.org, Id: c.Id,
		Body: &gen.DeployCredentialUpdate{Name: "tok2", Config: map[string]interface{}{}}})
	wantStatus(t, err, 422)

	// Reveal: global admin only, audited, no-store.
	req := gen.RevealDeployCredentialSecretRequestObject{OrgId: f.org, Id: c.Id, Body: &gen.DeployCredentialRevealRequest{Field: "token"}}
	_, err = f.srv.RevealDeployCredentialSecret(admin, req)
	wantStatus(t, err, 403)
	out, err := f.srv.RevealDeployCredentialSecret(f.as("admin"), req)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.(gen.RevealDeployCredentialSecret200JSONResponse); got.Body.Value != "s3cret-value" || got.Headers.CacheControl != "no-store" {
		t.Fatalf("reveal = %+v", got)
	}
	if n := f.auditCount(t, "deploy_credential.secret_revealed"); n != 1 {
		t.Fatalf("reveal audit rows = %d, want 1", n)
	}
	req.Body.Field = "bogus"
	_, err = f.srv.RevealDeployCredentialSecret(f.as("admin"), req)
	wantStatus(t, err, 422)

	if _, err := f.srv.DeleteDeployCredential(admin, gen.DeleteDeployCredentialRequestObject{OrgId: f.org, Id: c.Id}); err != nil {
		t.Fatal(err)
	}
}

func TestDeployCredentialAttachGateAndDelete(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Never)
	admin, op := f.as("org-admin"), f.as("operator")
	tok := f.createCred(t, "tok", "token", map[string]interface{}{"token": "s3cret-value"})
	apiKey := f.createCred(t, "key", "apiKey", map[string]interface{}{"apiKey": "k"})
	cfg := map[string]interface{}{"url": "https://a.example.test"}

	// An operator cannot attach a credential.
	_, err := f.createTargetWith(op, "t-op", gen.RunsOn("server"), cfg, &tok.Id)
	wantStatus(t, err, 403)
	// Kind mismatch, unknown credential, and a config that also sets a supplied field: 422.
	_, err = f.createTargetWith(admin, "t-kind", gen.RunsOn("server"), cfg, &apiKey.Id)
	wantStatus(t, err, 422)
	unknown := uuid.New()
	_, err = f.createTargetWith(admin, "t-unknown", gen.RunsOn("server"), cfg, &unknown)
	wantStatus(t, err, 422)
	_, err = f.createTargetWith(admin, "t-dup", gen.RunsOn("server"), map[string]interface{}{"url": "https://a.example.test", "token": "own"}, &tok.Id)
	wantStatus(t, err, 422)

	tgt, err := f.createTargetWith(admin, "t1", gen.RunsOn("server"), cfg, &tok.Id)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.CredentialId == nil || *tgt.CredentialId != tok.Id || len(tgt.StoredSecrets) != 0 {
		t.Fatalf("target = %+v", tgt)
	}
	if b, _ := json.Marshal(tgt); strings.Contains(string(b), "s3cret-value") {
		t.Fatal("target response leaks the credential secret")
	}
	if used := func() int {
		r, _ := f.srv.GetDeployCredential(admin, gen.GetDeployCredentialRequestObject{OrgId: f.org, Id: tok.Id})
		return *r.(gen.GetDeployCredential200JSONResponse).UsedBy
	}(); used != 1 {
		t.Fatalf("usedBy = %d, want 1", used)
	}

	// Operators may edit a credential-backed target, but not its URL.
	if err := f.updateTargetWith(op, tgt, "t1-renamed", cfg, &tok.Id); err != nil {
		t.Fatalf("operator rename: %v", err)
	}
	err = f.updateTargetWith(op, tgt, "t1-renamed", map[string]interface{}{"url": "https://evil.example.test"}, &tok.Id)
	wantStatus(t, err, 403)
	if err := f.updateTargetWith(admin, tgt, "t1-renamed", map[string]interface{}{"url": "https://b.example.test"}, &tok.Id); err != nil {
		t.Fatalf("org-admin url change: %v", err)
	}

	// Delete is blocked and names the target.
	_, err = f.srv.DeleteDeployCredential(admin, gen.DeleteDeployCredentialRequestObject{OrgId: f.org, Id: tok.Id})
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "t1-renamed") {
		t.Fatalf("409 = %v, want the target named", err)
	}

	// Detach with its own secret, then delete.
	if err := f.updateTargetWith(op, tgt, "t1-renamed", map[string]interface{}{"url": "https://b.example.test", "token": "own"}, nil); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := f.srv.DeleteDeployCredential(admin, gen.DeleteDeployCredentialRequestObject{OrgId: f.org, Id: tok.Id}); err != nil {
		t.Fatal(err)
	}

	// An embedded-secret target is unaffected by any of this.
	own, err := f.createTargetWith(op, "t-own", gen.RunsOn("server"), map[string]interface{}{"url": "https://a.example.test", "token": "own"}, nil)
	if err != nil || own.CredentialId != nil || len(own.StoredSecrets) != 1 {
		t.Fatalf("embedded target = %+v, %v", own, err)
	}
}

// credFile is an agent-side file target whose token comes from a credential.
type credFile struct{ targetstest.File }

func (c *credFile) Schema() json.RawMessage {
	return json.RawMessage(`{"credentialKinds":["token"],"type":"object","additionalProperties":false,"required":["dir","token"],
  "properties":{"dir":{"type":"string"},"token":{"type":"string","secret":true}}}`)
}

func (c *credFile) Parse(raw json.RawMessage) (targets.Config, error) {
	var doc struct{ Dir, Token string }
	if err := json.Unmarshal(raw, &doc); err != nil {
		return targets.Config{}, err
	}
	pub, secrets, err := targets.Split(c.Schema(), raw)
	if err != nil {
		return targets.Config{}, err
	}
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: true}, nil
}

func TestDeployCredentialRotationReachesDeploys(t *testing.T) {
	f := newAgentFixture(t)
	sec := f.registerTestSecret("test-secret", targets.Server, targets.Never)
	f.srv.d.Targets.Register(&credFile{File: targetstest.File{Code: "cred-file"}})
	admin, op := f.as("org-admin"), f.as("operator")
	ctx := context.Background()
	tok := f.createCred(t, "tok", "token", map[string]interface{}{"token": "first"})

	// Server deploy: the credential's token is in the target request.
	tgt, err := f.createTargetWith(admin, "srv", gen.RunsOn("server"), map[string]interface{}{"url": "https://a.example.test"}, &tok.Id)
	if err != nil {
		t.Fatal(err)
	}
	certID, v1 := f.currentCert(t, "rot")
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: tgt.Id, Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	tokenOf := func(c targets.Request) string {
		var m map[string]interface{}
		_ = json.Unmarshal(c.Config, &m)
		s, _ := m["token"].(string)
		return s
	}
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err != nil {
		t.Fatal(err)
	}
	if len(sec.Calls) != 1 || tokenOf(sec.Calls[0]) != "first" {
		t.Fatalf("first deploy calls = %+v", sec.Calls)
	}

	// Agent target on the same credential.
	client := f.activeClient(t, "agent-1")
	agentT, err := f.srv.CreateDeployTarget(admin, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "agt", Type: "cred-file", Config: map[string]interface{}{"dir": "/etc/ssl/x"}, CredentialId: &tok.Id}})
	if err != nil {
		t.Fatal(err)
	}
	at := agentT.(gen.CreateDeployTarget201JSONResponse)
	if _, err := f.srv.CreateGrant(f.as("admin"), gen.CreateGrantRequestObject{OrgId: f.org, Id: client.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: "pull", DeployTargetId: &at.Id}}); err != nil {
		t.Fatal(err)
	}
	agentToken := func() string {
		as, err := f.svc.Assignments(ctx, client)
		if err != nil || len(as.Grants) != 1 || as.Grants[0].Target == nil {
			t.Fatalf("assignments = %+v, %v", as, err)
		}
		var m map[string]interface{}
		_ = json.Unmarshal(as.Grants[0].Target.Config, &m)
		s, _ := m["token"].(string)
		return s
	}
	if got := agentToken(); got != "first" {
		t.Fatalf("agent token = %q, want first", got)
	}
	before, err := f.q.GetClientByID(ctx, client.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate.
	if _, err := f.srv.UpdateDeployCredential(admin, gen.UpdateDeployCredentialRequestObject{OrgId: f.org, Id: tok.Id,
		Body: &gen.DeployCredentialUpdate{Name: "tok", Config: map[string]interface{}{"token": "second"}}}); err != nil {
		t.Fatal(err)
	}
	if got := agentToken(); got != "second" {
		t.Fatalf("agent token after rotation = %q, want second", got)
	}
	after, err := f.q.GetClientByID(ctx, client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.DesiredRevision <= before.DesiredRevision {
		t.Fatalf("client revision %d -> %d, want a bump so the agent re-syncs", before.DesiredRevision, after.DesiredRevision)
	}
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err != nil {
		t.Fatal(err)
	}
	if len(sec.Calls) != 2 || tokenOf(sec.Calls[1]) != "second" {
		t.Fatalf("second deploy calls = %+v", sec.Calls)
	}
}

func TestDeployCredentialSSHHostKeyGateAndOwnSecrets(t *testing.T) {
	f := newAgentFixture(t)
	if _, ok := f.srv.d.Targets.Get("ssh"); !ok {
		f.srv.d.Targets.Register(deploy.SSH{})
	}
	admin, op := f.as("org-admin"), f.as("operator")
	cred := f.createCred(t, "sshpw", "password", map[string]interface{}{"username": "root", "password": "pw"})
	line := func() string {
		s, _ := sshxtest.NewSigner(t)
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	}
	hk1, hk2 := line(), line()
	cfg := func(hostKey string, extra map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{"host": "h.example.test", "hostKey": hostKey,
			"files": []map[string]interface{}{{"path": "/etc/c.crt", "content": "cert"}}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	_, ownPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownBlk, err := ssh.MarshalPrivateKey(ownPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	runsOn := gen.RunsOn("server")
	res, err := f.srv.CreateDeployTarget(admin, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "ssh1", Type: "ssh", RunsOn: &runsOn, Config: cfg(hk1, map[string]interface{}{"privateKey": string(pem.EncodeToMemory(ownBlk))}), CredentialId: &cred.Id}})
	if err != nil {
		t.Fatal(err)
	}
	tgt := gen.DeployTarget(res.(gen.CreateDeployTarget201JSONResponse))
	upd := func(ctx context.Context, c map[string]interface{}) error {
		_, err := f.srv.UpdateDeployTarget(ctx, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: tgt.Id,
			Body: &gen.DeployTargetInput{Name: "ssh1", Type: "ssh", Config: c, CredentialId: &cred.Id}})
		return err
	}

	// The target's own privateKey survives an edit that sends __unchanged__.
	if err := upd(op, cfg(hk1, map[string]interface{}{"privateKey": "__unchanged__"})); err != nil {
		t.Fatalf("edit keeping own secret: %v", err)
	}
	// A credential-supplied field still cannot be set on the target.
	wantStatus(t, upd(admin, cfg(hk1, map[string]interface{}{"password": "x"})), 422)
	// Swapping the pinned host key needs deploycreds:write.
	wantStatus(t, upd(op, cfg(hk2, map[string]interface{}{"privateKey": "__unchanged__"})), 403)
	if err := upd(admin, cfg(hk2, map[string]interface{}{"privateKey": "__unchanged__"})); err != nil {
		t.Fatalf("org-admin host key change: %v", err)
	}
}

func TestDeployCredentialSSHKeyCheck(t *testing.T) {
	f := newAgentFixture(t)
	admin := f.as("org-admin")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	enc := string(pem.EncodeToMemory(blk))
	create := func(name string, cfg map[string]interface{}) error {
		_, err := f.srv.CreateDeployCredential(admin, gen.CreateDeployCredentialRequestObject{OrgId: f.org,
			Body: &gen.DeployCredentialInput{Name: name, Kind: "ssh", Config: cfg}})
		return err
	}
	err = create("junk", map[string]interface{}{"username": "root", "privateKey": "junk"})
	wantStatus(t, err, 422)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Title, "config.privateKey") {
		t.Fatalf("err = %v", err)
	}
	wantStatus(t, create("nopass", map[string]interface{}{"username": "root", "privateKey": enc}), 422)
	if err := create("ok", map[string]interface{}{"username": "root", "privateKey": enc, "privateKeyPassphrase": "pw"}); err != nil {
		t.Fatal(err)
	}
}

func TestListDeployTargetsFiltersByCredential(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Never)
	admin := f.as("org-admin")
	tok := f.createCred(t, "tok", "token", map[string]interface{}{"token": "s3cret-value"})
	cfg := map[string]interface{}{"url": "https://a.example.test"}
	if _, err := f.createTargetWith(admin, "with-cred", gen.RunsOn("server"), cfg, &tok.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.createTargetWith(admin, "plain", gen.RunsOn("server"), map[string]interface{}{"url": "https://b.example.test", "token": "own"}, nil); err != nil {
		t.Fatal(err)
	}
	list := func(ctx context.Context, id *uuid.UUID) []gen.DeployTarget {
		res, err := f.srv.ListDeployTargets(ctx, gen.ListDeployTargetsRequestObject{OrgId: f.org, Params: gen.ListDeployTargetsParams{CredentialId: id}})
		if err != nil {
			t.Fatal(err)
		}
		return res.(gen.ListDeployTargets200JSONResponse).Items
	}
	if got := list(admin, &tok.Id); len(got) != 1 || got[0].Name != "with-cred" {
		t.Fatalf("filtered = %+v", got)
	}
	other := uuid.New()
	if got := list(admin, &other); len(got) != 0 {
		t.Fatalf("unknown credential = %+v", got)
	}
	if got := list(admin, nil); len(got) != 2 {
		t.Fatalf("unfiltered = %d, want 2", len(got))
	}
}
