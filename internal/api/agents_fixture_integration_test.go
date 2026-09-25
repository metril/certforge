//go:build integration

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

// fakeHub records what the agents service sends to sockets.
type fakeHub struct {
	mu         sync.Mutex
	sent       map[uuid.UUID][]agentproto.Message
	closed     map[uuid.UUID]int
	online     map[uuid.UUID]bool
	broadcasts []agentproto.Message
}

func newFakeHub() *fakeHub {
	return &fakeHub{sent: map[uuid.UUID][]agentproto.Message{}, closed: map[uuid.UUID]int{}, online: map[uuid.UUID]bool{}}
}

func (h *fakeHub) Send(id uuid.UUID, m agentproto.Message) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent[id] = append(h.sent[id], m)
	return h.online[id]
}

func (h *fakeHub) Close(id uuid.UUID, code int, _ string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed[id] = code
}

func (h *fakeHub) Connected(id uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.online[id]
}

func (h *fakeHub) Broadcast(m agentproto.Message) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcasts = append(h.broadcasts, m)
	return len(h.online)
}

func (h *fakeHub) messages(id uuid.UUID) []agentproto.Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]agentproto.Message(nil), h.sent[id]...)
}

type agentFixture struct {
	*apiFixture
	svc *agents.Service
	ca  *agentca.Store
	q   *sqlcgen.Queries
	hub *fakeHub
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	f := newAPIFixture(t)
	q := sqlcgen.New(f.pool)
	ca := agentca.NewStore(f.pool, cryptotest.PrefixBox{})
	hub := newFakeHub()
	svc := &agents.Service{Pool: f.pool, Q: q, CA: ca, Certs: f.certs, Auditor: f.srv.d.Auditor, Hub: hub,
		Settings: agents.StaticSettings(agents.Settings{}, "https://cf.example.test"), Log: slog.Default()}
	f.srv.d.Queries = q
	f.srv.d.Agents = svc
	f.srv.d.Issuance.RenameHook = svc.ResyncCertificateRename
	return &agentFixture{apiFixture: f, svc: svc, ca: ca, q: q, hub: hub}
}

// newClient creates a pending client through the service as an operator.
func (f *agentFixture) newClient(t *testing.T, name string) agents.Enrolment {
	t.Helper()
	e, err := f.svc.CreateClient(f.as("operator"), f.org, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// activeClient creates a client and marks it enrolled without an agent.
func (f *agentFixture) activeClient(t *testing.T, name string) sqlcgen.Client {
	t.Helper()
	e := f.newClient(t, name)
	active, err := f.ca.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var c sqlcgen.Client
	if _, err := f.pool.Exec(context.Background(), `UPDATE clients SET status = 'active', agent_cert_serial = 'ab',
		agent_cert_not_after = $2, agent_ca_id = $3 WHERE id = $1`, e.Client.ID, time.Now().Add(24*time.Hour), active.ID); err != nil {
		t.Fatal(err)
	}
	c, err = f.q.GetClientByID(context.Background(), e.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// currentCert stores an issued certificate and makes the version current.
func (f *agentFixture) currentCert(t *testing.T, name string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	c, v := f.issuedCert(t, name)
	if _, err := f.pool.Exec(context.Background(), `UPDATE certificates SET current_version_id = $2, status = 'active' WHERE id = $1`, c.ID, v.ID); err != nil {
		t.Fatal(err)
	}
	return c.ID, v.ID
}

// layout stores a one-file fullchain layout.
func (f *agentFixture) layout(t *testing.T, name, path string) uuid.UUID {
	t.Helper()
	files, _ := json.Marshal([]delivery.OutputFile{{Path: path, Format: "pem", Parts: []string{"fullchain"}, Mode: "0644"}})
	l, err := f.q.CreateLayout(context.Background(), sqlcgen.CreateLayoutParams{OrgID: f.org, Name: name, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	return l.ID
}
