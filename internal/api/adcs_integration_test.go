//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/signer/adcs/adcstest"
)

// TestADCSCACreateUpdate covers adcs CA create/update over a fake AD CS: the
// loopback URL policy applies, create reads the policy (template OID, CES
// URL, trust bundle), the password is never returned and is kept by omitting
// it or sending __unchanged__.
func TestADCSCACreateUpdate(t *testing.T) {
	f := newAPIFixture(t)
	fk := adcstest.New(t)
	cfg := func(pw any) *map[string]interface{} {
		m := map[string]interface{}{"cepUrl": fk.CEPURL, "template": adcstest.Template, "username": adcstest.Username,
			"caBundlePem": fk.TLSCAPEM}
		if pw != nil {
			m["password"] = pw
		}
		return &m
	}
	create := func(name string, pw any) (gen.CreateCaResponseObject, error) {
		return f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org,
			Body: &gen.CAInput{Name: name, Type: ptrT(gen.Adcs), Config: cfg(pw)}})
	}

	// Loopback is refused until the notifications setting allows it.
	_, err := create("Corp", adcstest.Password)
	wantStatus(t, err, http.StatusUnprocessableEntity)
	if err := f.settingsStore.Set(context.Background(), "section.notifications", map[string]any{"allowLoopbackUrls": true}); err != nil {
		t.Fatal(err)
	}

	_, err = create("Corp", nil)
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = create("Corp", "wrong")
	wantStatus(t, err, http.StatusUnprocessableEntity)

	res, err := create("Corp", adcstest.Password)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ca := gen.CA(res.(gen.CreateCa201JSONResponse))
	if ca.Type != gen.Adcs || ca.Config["templateOid"] != "1.3.6.1.4.1.311.21.8.1.2" || ca.Config["cesUrl"] != fk.CESURL ||
		ca.TrustBundlePem == "" || len(ca.StoredSecrets) != 1 || ca.StoredSecrets[0] != "password" {
		t.Fatalf("ca = %+v", ca)
	}
	if _, ok := ca.Config["password"]; ok {
		t.Fatal("password returned in config")
	}

	update := func(name string, pw any) error {
		_, err := f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: ca.Id,
			Body: &gen.CAInput{Name: name, Type: ptrT(gen.Adcs), Config: cfg(pw)}})
		return err
	}
	if err := update("Corp renamed", "__unchanged__"); err != nil {
		t.Fatalf("update sentinel: %v", err)
	}
	if err := update("Corp renamed 2", nil); err != nil {
		t.Fatalf("update omitted: %v", err)
	}
	wantStatus(t, update("Corp renamed 3", "wrong"), http.StatusUnprocessableEntity)
}

// TestADCSProbe covers the template probe: templates listed, an unusable
// template reported, the saved-CA __unchanged__ password path, a bad password
// as ok false, the URL policy, and 403 for roles without cas:write.
func TestADCSProbe(t *testing.T) {
	f := newAPIFixture(t)
	fk := adcstest.New(t)
	if err := f.settingsStore.Set(context.Background(), "section.notifications", map[string]any{"allowLoopbackUrls": true}); err != nil {
		t.Fatal(err)
	}
	body := func(pw string) *gen.AdcsProbeRequest {
		return &gen.AdcsProbeRequest{CepUrl: fk.CEPURL, Username: adcstest.Username, Password: &pw,
			CaBundlePem: &fk.TLSCAPEM, Template: ptrT(adcstest.Template)}
	}
	probe := func(ctx context.Context, b *gen.AdcsProbeRequest) (gen.AdcsProbeResult, error) {
		res, err := f.srv.ProbeAdcs(ctx, gen.ProbeAdcsRequestObject{OrgId: f.org, Body: b})
		if err != nil {
			return gen.AdcsProbeResult{}, err
		}
		return gen.AdcsProbeResult(res.(gen.ProbeAdcs200JSONResponse)), nil
	}

	res, err := probe(f.as("admin"), body(adcstest.Password))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ok || len(res.Templates) != 1 || res.Templates[0].Name != adcstest.Template || !res.Templates[0].CanEnroll ||
		res.Templates[0].RequiresApproval || res.Templates[0].MinKeySize != 2048 || res.Selected == nil || !res.Selected.Usable {
		t.Fatalf("res = %+v selected=%+v", res, res.Selected)
	}

	// A template that is unknown or held for approval is reported, not an error.
	b := body(adcstest.Password)
	b.Template = ptrT("Nope")
	if res, err = probe(f.as("admin"), b); err != nil || !res.Ok || res.Selected == nil || res.Selected.Usable || res.Selected.Reason == nil {
		t.Fatalf("unknown template: %+v %v", res, err)
	}
	fk.EnrollmentFlags.Store(0x2)
	res, err = probe(f.as("admin"), body(adcstest.Password))
	if err != nil || !res.Ok || !res.Templates[0].RequiresApproval || res.Selected.Usable || res.Selected.Reason == nil {
		t.Fatalf("approval template: %+v %v", res, err)
	}
	fk.EnrollmentFlags.Store(0)

	// Wrong password: 200 with ok false and no template list.
	res, err = probe(f.as("admin"), body("wrong"))
	if err != nil || res.Ok || res.Error == nil || len(res.Templates) != 0 {
		t.Fatalf("bad password: %+v %v", res, err)
	}

	// Saved CA: __unchanged__ reuses its stored password.
	created, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Corp", Type: ptrT(gen.Adcs), Config: &map[string]interface{}{"cepUrl": fk.CEPURL, "template": adcstest.Template,
			"username": adcstest.Username, "caBundlePem": fk.TLSCAPEM, "password": adcstest.Password}}})
	if err != nil {
		t.Fatal(err)
	}
	ca := gen.CA(created.(gen.CreateCa201JSONResponse))
	b = body("__unchanged__")
	b.CaId = &ca.Id
	if res, err = probe(f.as("admin"), b); err != nil || !res.Ok || len(res.Templates) != 1 {
		t.Fatalf("unchanged: %+v %v", res, err)
	}
	// Without caId, or with a caId that is not in the org, it is refused.
	_, err = probe(f.as("admin"), body("__unchanged__"))
	wantStatus(t, err, http.StatusUnprocessableEntity)
	b = body("__unchanged__")
	other := uuid.New()
	b.CaId = &other
	_, err = probe(f.as("admin"), b)
	wantStatus(t, err, http.StatusNotFound)

	// URL policy: a non-https URL is refused.
	b = body(adcstest.Password)
	b.CepUrl = "http://example.test/cep"
	_, err = probe(f.as("admin"), b)
	wantStatus(t, err, http.StatusUnprocessableEntity)

	// cas:write is required.
	_, err = probe(f.as("viewer"), body(adcstest.Password))
	wantStatus(t, err, http.StatusForbidden)
	_, err = probe(f.as("operator"), body(adcstest.Password))
	wantStatus(t, err, http.StatusForbidden)

	// The audit trail records probes without the password.
	if n := f.auditCount(t, "ca.adcs_probe"); n == 0 {
		t.Fatal("no ca.adcs_probe audit rows")
	}
}
