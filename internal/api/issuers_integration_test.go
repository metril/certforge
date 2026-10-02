//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/issuance"
)

func TestCaPresetsListed(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.ListCaPresets(f.as("viewer"), gen.ListCaPresetsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	ps := res.(gen.ListCaPresets200JSONResponse)
	if len(ps) != 7 || ps[0].Preset != "letsencrypt" || !ps[2].RequiresEab {
		t.Fatalf("presets = %+v", ps)
	}
}

func TestCreateCaPermissionsAndValidation(t *testing.T) {
	f := newAPIFixture(t)
	_, err := f.srv.CreateCa(f.as("operator"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: ptr(gen.CAPresetCode("letsencrypt"))}})
	wantStatus(t, err, http.StatusForbidden) // cas:write is global-admin only
	_, err = f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "Zero", Preset: ptr(gen.CAPresetCode("zerossl"))}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: ptr(gen.CAPresetCode("letsencrypt"))}})
	if err != nil {
		t.Fatal(err)
	}
	if ca := res.(gen.CreateCa201JSONResponse); ca.DirectoryUrl != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("ca = %+v", ca)
	}
	if n := f.auditCount(t, "ca.create"); n != 1 {
		t.Fatalf("ca.create audit count = %d", n)
	}
	list, err := f.srv.ListCas(f.as("viewer"), gen.ListCasRequestObject{OrgId: f.org})
	if err != nil || len(list.(gen.ListCas200JSONResponse)) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
}

func TestUpdateAndDeleteCaAudited(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: ptr(gen.CAPresetCode("letsencrypt"))}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	if _, err := f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: ca.Id,
		Body: &gen.CAInput{Name: "LE2", Preset: ptr(gen.CAPresetCode("letsencrypt"))}}); err != nil {
		t.Fatal(err)
	}
	if n := f.auditCount(t, "ca.update"); n != 1 {
		t.Fatalf("ca.update audit count = %d", n)
	}
	if _, err := f.srv.DeleteCa(f.as("admin"), gen.DeleteCaRequestObject{OrgId: f.org, Id: ca.Id}); err != nil {
		t.Fatal(err)
	}
	if n := f.auditCount(t, "ca.delete"); n != 1 {
		t.Fatalf("ca.delete audit count = %d", n)
	}
	_, err = f.srv.GetCa(f.as("admin"), gen.GetCaRequestObject{OrgId: f.org, Id: ca.Id})
	wantStatus(t, err, http.StatusNotFound)
}

func TestDeleteCaBlockedWhileReferenced(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: ptr(gen.CAPresetCode("letsencrypt"))}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	if _, err := f.srv.CreateAcmeAccount(f.as("operator"), gen.CreateAcmeAccountRequestObject{OrgId: f.org,
		Body: &gen.AcmeAccountInput{CaId: ca.Id, Email: "a@example.test"}}); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.DeleteCa(f.as("admin"), gen.DeleteCaRequestObject{OrgId: f.org, Id: ca.Id})
	wantStatus(t, err, http.StatusConflict)
}

func TestAcmeAccountLifecycleAudited(t *testing.T) {
	f := newAPIFixture(t)
	caRes, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: ptr(gen.CAPresetCode("letsencrypt"))}})
	if err != nil {
		t.Fatal(err)
	}
	ca := caRes.(gen.CreateCa201JSONResponse)
	res, err := f.srv.CreateAcmeAccount(f.as("operator"), gen.CreateAcmeAccountRequestObject{OrgId: f.org,
		Body: &gen.AcmeAccountInput{CaId: ca.Id, Email: "a@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	acct := res.(gen.CreateAcmeAccount201JSONResponse)
	if n := f.auditCount(t, "acme_account.create"); n != 1 {
		t.Fatalf("acme_account.create audit count = %d", n)
	}
	if _, err := f.srv.DeleteAcmeAccount(f.as("operator"), gen.DeleteAcmeAccountRequestObject{OrgId: f.org, Id: acct.Id}); err != nil {
		t.Fatal(err)
	}
	if n := f.auditCount(t, "acme_account.delete"); n != 1 {
		t.Fatalf("acme_account.delete audit count = %d", n)
	}
}

func TestGlobalIssuanceDefaultsValidated(t *testing.T) {
	f := newAPIFixture(t)
	// Syntactically malformed: the schema's format: uuid is an annotation
	// only, not asserted, so this must be caught after schema validation
	// (json.Unmarshal into issuance.Defaults) and still reported as 422,
	// not 400 (review fix round 1, item 2).
	_, err := f.srv.PutSettingsSection(f.as("admin"), gen.PutSettingsSectionRequestObject{Section: "issuance_defaults",
		Body: &gen.SettingsValue{"caId": "not-a-uuid"}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	bogus := uuid.New().String()
	_, err = f.srv.PutSettingsSection(f.as("admin"), gen.PutSettingsSectionRequestObject{Section: "issuance_defaults",
		Body: &gen.SettingsValue{"caId": bogus}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	caRes, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: ptr(gen.CAPresetCode("letsencrypt"))}})
	if err != nil {
		t.Fatal(err)
	}
	ca := caRes.(gen.CreateCa201JSONResponse)
	res, err := f.srv.PutSettingsSection(f.as("admin"), gen.PutSettingsSectionRequestObject{Section: "issuance_defaults",
		Body: &gen.SettingsValue{"caId": ca.Id.String()}})
	if err != nil {
		t.Fatal(err)
	}
	sec := res.(gen.PutSettingsSection200JSONResponse)
	if sec.Value["caId"] != ca.Id.String() {
		t.Fatalf("stored section = %+v", sec)
	}
}

func TestOtherOrgIsForbidden(t *testing.T) {
	f := newAPIFixture(t)
	other := newAPIFixture(t)
	_, err := f.srv.ListAcmeAccounts(other.as("operator"), gen.ListAcmeAccountsRequestObject{OrgId: f.org})
	wantStatus(t, err, http.StatusForbidden)
}

func TestEffectiveDefaultsShowSources(t *testing.T) {
	f := newAPIFixture(t)
	secs := 600
	if _, err := f.srv.PutOrgIssuanceDefaults(f.as("operator"), gen.PutOrgIssuanceDefaultsRequestObject{OrgId: f.org,
		Body: &gen.IssuanceDefaults{PropagationSeconds: &secs}}); err != nil {
		t.Fatal(err)
	}
	if n := f.auditCount(t, "issuance_defaults.update"); n != 1 {
		t.Fatalf("issuance_defaults.update audit count = %d", n)
	}
	res, err := f.srv.GetEffectiveIssuanceDefaults(f.as("viewer"), gen.GetEffectiveIssuanceDefaultsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	e := res.(gen.GetEffectiveIssuanceDefaults200JSONResponse)
	if e.PropagationSeconds.Value != 600 || e.PropagationSeconds.Source != "org" || e.KeyType.Value != "ec256" || e.KeyType.Source != "default" {
		t.Fatalf("effective = %+v", e)
	}
	bad := gen.KeyType("dsa")
	_, err = f.srv.PutOrgIssuanceDefaults(f.as("operator"), gen.PutOrgIssuanceDefaultsRequestObject{OrgId: f.org, Body: &gen.IssuanceDefaults{KeyType: &bad}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// The built-ins served beside the effective values are issuance.BuiltinDefaults,
// so the web client carries no copy of them.
func TestEffectiveDefaultsServeBuiltins(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.GetEffectiveIssuanceDefaults(f.as("viewer"), gen.GetEffectiveIssuanceDefaultsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	// Compare as JSON objects, dropping nulls: the generated type writes an
	// unset nullable field as null where BuiltinDefaults omits it.
	norm := func(v any) map[string]any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		for k, x := range m {
			if x == nil {
				delete(m, k)
			}
		}
		return m
	}
	got := norm(res.(gen.GetEffectiveIssuanceDefaults200JSONResponse).Builtin)
	want := norm(issuance.BuiltinDefaults())
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("builtin = %v, want %v", got, want)
	}
}
