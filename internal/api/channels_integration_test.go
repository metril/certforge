//go:build integration

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/notify"
)

// apiKeyPrincipal returns a context for an API key scoped to scopes, bound
// to org via the viewer role (the widest role that still lets scope alone
// decide what the key may do — the same shape TestListAllCertificatesAPIKeyScoped
// uses).
func apiKeyPrincipal(org uuid.UUID, scopes []string) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{
		Kind: authn.KindAPIKey, UserID: uuid.New(), OrgIDs: []uuid.UUID{org},
		Bindings: []authn.Binding{{Role: authz.RoleOperator, OrgID: &org}},
		APIKey:   &authn.APIKeyInfo{ID: uuid.New(), Scopes: scopes, OrgID: &org},
	})
}

func webhookInput(name, url string) *gen.ChannelInput {
	return &gen.ChannelInput{Name: name, Type: gen.Webhook, Config: map[string]interface{}{"url": url}}
}

func TestChannelCRUD(t *testing.T) {
	f := newNotifyFixture(t)

	res, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org,
		Body: webhookInput("ops-webhook", "https://hooks.example.test/abc")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created := res.(gen.CreateChannel201JSONResponse)
	if created.Name != "ops-webhook" || created.Type != gen.Webhook || created.Summary != "hooks.example.test" {
		t.Fatalf("create = %+v", created)
	}
	if len(created.StoredSecrets) != 1 || created.StoredSecrets[0] != "url" {
		t.Fatalf("storedSecrets = %v, want [url]", created.StoredSecrets)
	}
	if created.LastDelivery != nil {
		t.Fatalf("lastDelivery before any test = %+v, want nil", created.LastDelivery)
	}
	if created.MinSeverity != gen.Info || created.Enabled != true || len(created.Events) != 0 {
		t.Fatalf("defaults not applied: %+v", created)
	}
	if n := f.auditCount(t, "channel.create"); n != 1 {
		t.Fatalf("channel.create audit count = %d", n)
	}

	getRes, err := f.srv.GetChannel(f.as("viewer"), gen.GetChannelRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := gen.Channel(getRes.(gen.GetChannel200JSONResponse)); got.Id != created.Id {
		t.Fatalf("get = %+v", got)
	}

	listRes, err := f.srv.ListChannels(f.as("viewer"), gen.ListChannelsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if items := listRes.(gen.ListChannels200JSONResponse); len(items) != 1 || items[0].Id != created.Id {
		t.Fatalf("list = %+v", items)
	}

	// Update: rename and disable, url kept unchanged.
	upd := webhookInput("ops-webhook-renamed", notify.Unchanged)
	disabled := false
	upd.Enabled = &disabled
	updRes, err := f.srv.UpdateChannel(f.as("operator"), gen.UpdateChannelRequestObject{OrgId: f.org, Id: created.Id, Body: upd})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := updRes.(gen.UpdateChannel200JSONResponse)
	if updated.Name != "ops-webhook-renamed" || updated.Enabled {
		t.Fatalf("update = %+v", updated)
	}
	if updated.Summary != "hooks.example.test" {
		t.Fatalf("update summary = %q, want unchanged (hooks.example.test)", updated.Summary)
	}
	if n := f.auditCount(t, "channel.update"); n != 1 {
		t.Fatalf("channel.update audit count = %d", n)
	}

	if _, err := f.srv.DeleteChannel(f.as("operator"), gen.DeleteChannelRequestObject{OrgId: f.org, Id: created.Id}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := f.auditCount(t, "channel.delete"); n != 1 {
		t.Fatalf("channel.delete audit count = %d", n)
	}
	_, err = f.srv.GetChannel(f.as("viewer"), gen.GetChannelRequestObject{OrgId: f.org, Id: created.Id})
	wantStatus(t, err, http.StatusNotFound)
}

// TestChannelAuthzMatrix checks every operation against every role: read
// ops (list, get) need alerts:read; write ops (create, update, delete,
// test) need alerts:write. update/delete/test are checked against a
// nonexistent id, so a permitted role sees 404 (not 403) and a forbidden
// role sees 403 regardless of what exists — proving the authz gate runs
// before the resource lookup.
func TestChannelAuthzMatrix(t *testing.T) {
	f := newNotifyFixture(t)
	seedRes, err := f.srv.CreateChannel(f.as("admin"), gen.CreateChannelRequestObject{OrgId: f.org,
		Body: webhookInput("seed", "https://hooks.example.test/seed")})
	if err != nil {
		t.Fatal(err)
	}
	seedID := seedRes.(gen.CreateChannel201JSONResponse).Id
	missingID := uuid.New()

	canRead := map[string]bool{authz.RoleViewer: true, authz.RoleOperator: true, authz.RoleOrgAdmin: true, authz.RoleAdmin: true}
	canWrite := map[string]bool{authz.RoleViewer: false, authz.RoleOperator: true, authz.RoleOrgAdmin: true, authz.RoleAdmin: true}

	for _, role := range []string{authz.RoleViewer, authz.RoleOperator, authz.RoleOrgAdmin, authz.RoleAdmin} {
		ctx := f.as(role)

		_, err := f.srv.ListChannels(ctx, gen.ListChannelsRequestObject{OrgId: f.org})
		checkGate(t, role+"/list", err, canRead[role], http.StatusForbidden)

		_, err = f.srv.GetChannel(ctx, gen.GetChannelRequestObject{OrgId: f.org, Id: seedID})
		checkGate(t, role+"/get", err, canRead[role], http.StatusForbidden)

		_, err = f.srv.CreateChannel(ctx, gen.CreateChannelRequestObject{OrgId: f.org,
			Body: webhookInput("wh-"+role, "https://hooks.example.test/"+role)})
		checkGate(t, role+"/create", err, canWrite[role], http.StatusForbidden)

		_, err = f.srv.UpdateChannel(ctx, gen.UpdateChannelRequestObject{OrgId: f.org, Id: missingID, Body: webhookInput("x", "https://hooks.example.test/x")})
		checkGateEither(t, role+"/update", err, canWrite[role], http.StatusForbidden, http.StatusNotFound)

		_, err = f.srv.TestChannel(ctx, gen.TestChannelRequestObject{OrgId: f.org, Id: missingID})
		checkGateEither(t, role+"/test", err, canWrite[role], http.StatusForbidden, http.StatusNotFound)

		_, err = f.srv.DeleteChannel(ctx, gen.DeleteChannelRequestObject{OrgId: f.org, Id: missingID})
		checkGateEither(t, role+"/delete", err, canWrite[role], http.StatusForbidden, http.StatusNotFound)
	}

	// An API key scoped to alerts:read only may list/get, never write.
	roScoped := apiKeyPrincipal(f.org, []string{"alerts:read"})
	if _, err := f.srv.ListChannels(roScoped, gen.ListChannelsRequestObject{OrgId: f.org}); err != nil {
		t.Errorf("alerts:read key list: %v", err)
	}
	_, err = f.srv.CreateChannel(roScoped, gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("ro", "https://hooks.example.test/ro")})
	wantStatus(t, err, http.StatusForbidden)

	// An API key scoped to alerts:write may create and test.
	rwScoped := apiKeyPrincipal(f.org, []string{"alerts:write"})
	if _, err := f.srv.CreateChannel(rwScoped, gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("rw", "https://hooks.example.test/rw")}); err != nil {
		t.Errorf("alerts:write key create: %v", err)
	}
}

// checkGate asserts err is nil when allowed, or status when not.
func checkGate(t *testing.T, label string, err error, allowed bool, forbidden int) {
	t.Helper()
	if allowed && err != nil {
		t.Errorf("%s: allowed role got error: %v", label, err)
	}
	if !allowed {
		wantStatus(t, err, forbidden)
	}
}

// checkGateEither asserts, for an allowed role, that err is either nil or
// notFoundStatus (the target id does not exist), and for a disallowed
// role, that err is exactly forbidden — proving the permission check runs
// ahead of (and independent of) the resource lookup.
func checkGateEither(t *testing.T, label string, err error, allowed bool, forbidden, notFoundStatus int) {
	t.Helper()
	if allowed {
		if err == nil {
			return
		}
		if got := problemStatus(err); got != notFoundStatus {
			t.Errorf("%s: allowed role got status %d, want %d (missing id) or success", label, got, notFoundStatus)
		}
		return
	}
	wantStatus(t, err, forbidden)
}

// TestAllOrgsNeedsGlobalAdmin: submitting allOrgs true needs global
// settings:write (an org-admin, even of this very org, does not have it);
// the same gate applies on update, not only create.
func TestAllOrgsNeedsGlobalAdmin(t *testing.T) {
	f := newNotifyFixture(t)
	allOrgs := true
	in := &gen.ChannelInput{Name: "global-discord", Type: gen.Discord,
		Config: map[string]interface{}{"webhookUrl": "https://discord.com/api/webhooks/1/2"}, AllOrgs: &allOrgs}

	_, err := f.srv.CreateChannel(f.as(authz.RoleOrgAdmin), gen.CreateChannelRequestObject{OrgId: f.org, Body: in})
	wantStatus(t, err, http.StatusForbidden)

	res, err := f.srv.CreateChannel(f.as(authz.RoleAdmin), gen.CreateChannelRequestObject{OrgId: f.org, Body: in})
	if err != nil {
		t.Fatalf("admin create: %v", err)
	}
	created := res.(gen.CreateChannel201JSONResponse)
	if !created.AllOrgs {
		t.Fatal("allOrgs not set on the stored channel")
	}

	// Re-submitting the same allOrgs:true value on update also needs the
	// gate, even though it is not a change.
	_, err = f.srv.UpdateChannel(f.as(authz.RoleOrgAdmin), gen.UpdateChannelRequestObject{OrgId: f.org, Id: created.Id, Body: in})
	wantStatus(t, err, http.StatusForbidden)

	// An admin may turn allOrgs back off.
	noAllOrgs := false
	off := &gen.ChannelInput{Name: "global-discord", Type: gen.Discord,
		Config: map[string]interface{}{"webhookUrl": "https://discord.com/api/webhooks/1/2"}, AllOrgs: &noAllOrgs}
	updRes, err := f.srv.UpdateChannel(f.as(authz.RoleAdmin), gen.UpdateChannelRequestObject{OrgId: f.org, Id: created.Id, Body: off})
	if err != nil {
		t.Fatalf("admin turn off allOrgs: %v", err)
	}
	if updRes.(gen.UpdateChannel200JSONResponse).AllOrgs {
		t.Fatal("allOrgs still true after admin turned it off")
	}
}

// TestAllOrgsVisibleToGlobalAdminOnly: listChannels includes another org's
// all_orgs channel only for a global admin.
func TestAllOrgsVisibleToGlobalAdminOnly(t *testing.T) {
	f := newNotifyFixture(t)
	other := dbtest.Org(t, f.pool)
	allOrgs := true
	in := &gen.ChannelInput{Name: "global-discord", Type: gen.Discord,
		Config: map[string]interface{}{"webhookUrl": "https://discord.com/api/webhooks/1/2"}, AllOrgs: &allOrgs}
	res, err := f.srv.CreateChannel(f.as(authz.RoleAdmin), gen.CreateChannelRequestObject{OrgId: other, Body: in})
	if err != nil {
		t.Fatal(err)
	}
	globalID := res.(gen.CreateChannel201JSONResponse).Id

	// A non-admin listing f.org sees nothing (the all_orgs channel belongs
	// to a different org and the caller is not a global admin).
	listRes, err := f.srv.ListChannels(f.as(authz.RoleOperator), gen.ListChannelsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range listRes.(gen.ListChannels200JSONResponse) {
		if c.Id == globalID {
			t.Fatal("non-admin saw another org's all_orgs channel")
		}
	}

	// A global admin listing f.org also sees the other org's all_orgs channel.
	adminList, err := f.srv.ListChannels(f.as(authz.RoleAdmin), gen.ListChannelsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range adminList.(gen.ListChannels200JSONResponse) {
		if c.Id == globalID {
			found = true
		}
	}
	if !found {
		t.Fatal("global admin did not see the other org's all_orgs channel")
	}
}

// TestChannelReadNeverReturnsSecrets: create, get, list and the audit
// trail all surface only the derived summary/storedSecrets — never the
// raw secret value or any part of its URL beyond the hostname.
func TestChannelReadNeverReturnsSecrets(t *testing.T) {
	f := newNotifyFixture(t)
	const tokenMarker = "verysecretvalue123"
	secretURL := "https://hooks.example.test/abc?token=" + tokenMarker

	res, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("wh", secretURL)})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateChannel201JSONResponse)
	checkChannelNoSecret(t, gen.Channel(created), tokenMarker)

	getRes, err := f.srv.GetChannel(f.as("viewer"), gen.GetChannelRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatal(err)
	}
	checkChannelNoSecret(t, gen.Channel(getRes.(gen.GetChannel200JSONResponse)), tokenMarker)

	listRes, err := f.srv.ListChannels(f.as("viewer"), gen.ListChannelsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range listRes.(gen.ListChannels200JSONResponse) {
		checkChannelNoSecret(t, c, tokenMarker)
	}

	details := f.lastAuditDetails(t, "channel.create", created.Id.String())
	if strings.Contains(details, tokenMarker) || strings.Contains(details, "config") {
		t.Errorf("channel.create audit details leaked config/secret: %s", details)
	}

	// A problem body from a failing update (type immutable) must not echo
	// the stored secret either.
	_, err = f.srv.UpdateChannel(f.as("operator"), gen.UpdateChannelRequestObject{OrgId: f.org, Id: created.Id,
		Body: &gen.ChannelInput{Name: "wh", Type: gen.Discord, Config: map[string]interface{}{"webhookUrl": "https://discord.com/api/webhooks/1/2"}}})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("update err = %v, want *HTTPError", err)
	}
	if strings.Contains(httpErr.Detail, tokenMarker) {
		t.Errorf("problem body leaked secret: %s", httpErr.Detail)
	}
}

func checkChannelNoSecret(t *testing.T, c gen.Channel, tokenMarker string) {
	t.Helper()
	if c.Summary != "hooks.example.test" {
		t.Errorf("summary = %q, want hostname only", c.Summary)
	}
	if strings.Contains(c.Summary, tokenMarker) {
		t.Errorf("summary leaked the secret: %q", c.Summary)
	}
	if _, ok := c.Config["url"]; ok {
		t.Error("config still carries the secret url field")
	}
	if len(c.StoredSecrets) != 1 || c.StoredSecrets[0] != "url" {
		t.Errorf("storedSecrets = %v, want [url]", c.StoredSecrets)
	}
}

// TestChannelSummaryPerType (integration companion to the notify-package
// unit test of the same name): every type's summary round-trips through
// the API unchanged from notify.Summary's own output.
func TestChannelSummaryPerType(t *testing.T) {
	f := newNotifyFixture(t)
	cases := []struct {
		in   *gen.ChannelInput
		want string
	}{
		{webhookInput("wh", "https://hooks.example.test/x"), "hooks.example.test"},
		{&gen.ChannelInput{Name: "dc", Type: gen.Discord, Config: map[string]interface{}{"webhookUrl": "https://discord.com/api/webhooks/1/2"}}, "Discord webhook"},
		{&gen.ChannelInput{Name: "nt", Type: gen.Ntfy, Config: map[string]interface{}{"server": "https://ntfy.example.test", "topic": "alerts"}}, "ntfy.example.test/alerts"},
		{&gen.ChannelInput{Name: "ha", Type: gen.Homeassistant, Config: map[string]interface{}{"baseUrl": "https://ha.example.test:8123", "webhookId": "abc123"}}, "ha.example.test"},
		{&gen.ChannelInput{Name: "em", Type: gen.Smtp, Config: map[string]interface{}{"to": []string{"a@example.test", "b@example.test"}}}, "a@example.test, b@example.test"},
	}
	for _, c := range cases {
		res, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org, Body: c.in})
		if err != nil {
			t.Fatalf("%s: create: %v", c.in.Type, err)
		}
		if got := res.(gen.CreateChannel201JSONResponse).Summary; got != c.want {
			t.Errorf("%s: summary = %q, want %q", c.in.Type, got, c.want)
		}
	}
}

// TestChannelTypeImmutable: updateChannel with a different type than the
// stored channel's own is a 422 "type cannot change" (Shared contract,
// ChannelInput.type), even when the new type's config is itself valid.
func TestChannelTypeImmutable(t *testing.T) {
	f := newNotifyFixture(t)
	res, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("wh", "https://hooks.example.test/a")})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateChannel201JSONResponse)

	_, err = f.srv.UpdateChannel(f.as("operator"), gen.UpdateChannelRequestObject{OrgId: f.org, Id: created.Id,
		Body: &gen.ChannelInput{Name: "wh", Type: gen.Discord, Config: map[string]interface{}{"webhookUrl": "https://discord.com/api/webhooks/1/2"}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	// The channel itself is untouched.
	got, err := f.srv.GetChannel(f.as("viewer"), gen.GetChannelRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatal(err)
	}
	if gen.Channel(got.(gen.GetChannel200JSONResponse)).Type != gen.Webhook {
		t.Fatal("channel type changed despite the 422")
	}
}

// TestChannelLimitPerOrg: the 51st channel in an org is refused.
func TestChannelLimitPerOrg(t *testing.T) {
	f := newNotifyFixture(t)
	ctx := f.as("operator")
	for i := 0; i < 50; i++ {
		_, err := f.srv.CreateChannel(ctx, gen.CreateChannelRequestObject{OrgId: f.org,
			Body: webhookInput(fmt.Sprintf("wh-%02d", i), fmt.Sprintf("https://hooks.example.test/%d", i))})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	_, err := f.srv.CreateChannel(ctx, gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("one-too-many", "https://hooks.example.test/over")})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// TestTestChannelDelivers: a webhook fake receives the test event, and the
// result is delivered with a durationMs; lastDelivery and the channel.test
// audit event both follow.
func TestTestChannelDelivers(t *testing.T) {
	f := newNotifyFixture(t)
	f.allowLoopback(t)

	var gotEventHeader string
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEventHeader = r.Header.Get("X-CertForge-Event")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("wh", ts.URL+"/hook")})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateChannel201JSONResponse)

	testRes, err := f.srv.TestChannel(f.as("operator"), gen.TestChannelRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	dr := gen.DeliveryResult(testRes.(gen.TestChannel200JSONResponse))
	if dr.Status != gen.DeliveryStatusDelivered {
		errMsg := ""
		if dr.Error != nil {
			errMsg = *dr.Error
		}
		t.Fatalf("status = %q, want delivered (error=%q)", dr.Status, errMsg)
	}
	if dr.DurationMs < 0 {
		t.Errorf("durationMs = %d", dr.DurationMs)
	}
	if gotEventHeader != "test" {
		t.Errorf("X-CertForge-Event = %q, want test", gotEventHeader)
	}
	if len(gotBody) == 0 {
		t.Error("webhook fake received no body")
	}

	getRes, err := f.srv.GetChannel(f.as("viewer"), gen.GetChannelRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatal(err)
	}
	got := gen.Channel(getRes.(gen.GetChannel200JSONResponse))
	if got.LastDelivery == nil || got.LastDelivery.Status != gen.DeliveryStatusDelivered {
		t.Fatalf("lastDelivery = %+v, want delivered", got.LastDelivery)
	}
	if n := f.auditCount(t, "channel.test"); n != 1 {
		t.Errorf("channel.test audit count = %d", n)
	}
}

// TestTestChannelWorksWhenDisabled: testChannel is allowed on a disabled
// channel (Shared contract: "allowed when disabled").
func TestTestChannelWorksWhenDisabled(t *testing.T) {
	f := newNotifyFixture(t)
	f.allowLoopback(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer ts.Close()

	in := webhookInput("wh", ts.URL+"/hook")
	disabled := false
	in.Enabled = &disabled
	res, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org, Body: in})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateChannel201JSONResponse)
	if created.Enabled {
		t.Fatal("channel not created disabled")
	}
	testRes, err := f.srv.TestChannel(f.as("operator"), gen.TestChannelRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatalf("test on a disabled channel: %v", err)
	}
	if gen.DeliveryResult(testRes.(gen.TestChannel200JSONResponse)).Status != gen.DeliveryStatusDelivered {
		t.Fatal("disabled channel test did not deliver")
	}
}
