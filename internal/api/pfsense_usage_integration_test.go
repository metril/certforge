//go:build integration

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/deploy"
)

// pfTarget stores a pfsense deploy target pointing at url, with the password sealed.
func (f *agentFixture) pfTarget(t *testing.T, url string) uuid.UUID {
	t.Helper()
	pub, _ := json.Marshal(map[string]any{"url": url + "/api", "username": "admin", "timeoutSeconds": 5})
	sealed, err := f.box.Seal(context.Background(), []byte(`{"password":"pw"}`))
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO deploy_targets (org_id, name, type, runs_on, config, secret_cfg) VALUES ($1, $2, 'pfsense', 'server', $3, $4) RETURNING id`,
		f.org, "pf-"+uuid.NewString()[:8], pub, sealed).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGrantPfSenseUsage(t *testing.T) {
	f := newAgentFixture(t)
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			_, _ = io.WriteString(w, `{"token":"tok"}`)
		case "/api/mim/devices":
			_, _ = io.WriteString(w, `{"devices":[]}`)
		case "/api/system/certificates":
			_, _ = io.WriteString(w, `[{"refid":"abc123","descr":"web"}]`)
		case "/api/diag/cmd/php":
			_, _ = io.WriteString(w, `{"response":"CFJSON:{\"webgui\":true,\"services\":[{\"name\":\"ipsec\"}],\"packages\":[]}"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fw.Close()
	vaultT, _ := f.serverTarget(t, "vault", nil)
	f.srv.d.Targets.Register(deploy.PfSense{})
	pfT := f.pfTarget(t, fw.URL)
	certID, _ := f.currentCert(t, "web")
	otherCert, _ := f.currentCert(t, "other")
	grant := func(c uuid.UUID, target uuid.UUID) uuid.UUID {
		res, err := f.srv.CreateServerGrant(f.as("admin"), gen.CreateServerGrantRequestObject{OrgId: f.org, Id: target,
			Body: &gen.ServerGrantInput{CertificateId: c}})
		if err != nil {
			t.Fatal(err)
		}
		return res.(gen.CreateServerGrant201JSONResponse).Id
	}
	usage := func(id uuid.UUID) (gen.PfSenseUsage, error) {
		res, err := f.srv.GetGrantPfSenseUsage(f.as("viewer"), gen.GetGrantPfSenseUsageRequestObject{OrgId: f.org, Id: id})
		if err != nil {
			return gen.PfSenseUsage{}, err
		}
		return gen.PfSenseUsage(res.(gen.GetGrantPfSenseUsage200JSONResponse)), nil
	}
	u, err := usage(grant(certID, pfT))
	if err != nil || u.Refid == nil || *u.Refid != "abc123" || len(u.Services) != 2 || u.Services[0] != (gen.PfSenseService{Key: "webgui", Label: "WebGUI"}) || u.Services[1] != (gen.PfSenseService{Key: "ipsec", Label: "IPsec"}) {
		t.Fatalf("usage = %+v err=%v", u, err)
	}
	u, err = usage(grant(otherCert, pfT)) // certificate not on the firewall
	if err != nil || u.Refid != nil || len(u.Services) != 0 {
		t.Fatalf("absent = %+v err=%v", u, err)
	}
	if _, err := usage(grant(certID, vaultT)); problemStatus(err) != 422 {
		t.Fatalf("non-pfsense target: %v", err)
	}
	if _, err := usage(uuid.New()); problemStatus(err) != 404 {
		t.Fatalf("unknown grant: %v", err)
	}
}
