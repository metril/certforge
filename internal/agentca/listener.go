package agentca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/agentproto"
)

// Source is what the listener reads from the CA store.
type Source interface {
	Oldest(ctx context.Context) (*CA, error)
}

// Listener holds the agent listener's in-memory server certificate and the
// responder identity; TLSConfig reads the certificate on every handshake, so
// Reload takes effect without a restart. The listener asks for no client
// certificate: agents authenticate in the application layer (signed requests).
type Listener struct {
	Source Source
	Names  func(ctx context.Context) ([]string, error)
	Now    func() time.Time
	Log    *slog.Logger

	mu        sync.Mutex
	state     atomic.Pointer[listenerState]
	responder atomic.Pointer[Signer]
}

// Signer is the responder identity: the key that signs agent protocol
// responses and the certificate chain (leaf first) that vouches for it.
type Signer struct {
	Key   *ecdsa.PrivateKey
	Chain []*x509.Certificate
	CAID  uuid.UUID
}

// ErrNoNames means no listener names are configured, so the agent port has
// no TLS certificate. The responder identity is still renewed.
var ErrNoNames = errors.New("agentca: no listener names configured")

type listenerState struct {
	cert  tls.Certificate
	leaf  *x509.Certificate
	caID  uuid.UUID
	names []string
}

// ListenerInfo describes the served certificate.
type ListenerInfo struct {
	CAID     uuid.UUID
	Names    []string
	NotAfter time.Time
}

func (l *Listener) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Listener) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

// Responder returns the current responder identity; false before the first
// Reload.
func (l *Listener) Responder() (*Signer, bool) {
	s := l.responder.Load()
	return s, s != nil
}

func (l *Listener) reloadResponder(ca *CA) error {
	cur := l.responder.Load()
	if cur != nil && cur.CAID == ca.ID && !agentproto.RenewDue(cur.Chain[0].NotBefore, cur.Chain[0].NotAfter, l.now()) {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf, err := SignResponder(ca, &key.PublicKey, l.now())
	if err != nil {
		return err
	}
	l.responder.Store(&Signer{Key: key, Chain: []*x509.Certificate{leaf, ca.Cert}, CAID: ca.ID})
	l.log().Info("agent responder certificate issued", "ca", ca.ID, "not_after", leaf.NotAfter)
	return nil
}

// Reload rebuilds the trust pool and re-issues the server certificate when
// there is none, the signing CA or the names changed, or two thirds of its
// lifetime have passed. The oldest non-retired CA signs it: agents that have
// not received a newer bundle still trust it, so a rotation switches the
// listener only when the old CA is retired. The responder certificate (24 h)
// is renewed first and regardless of names, so it stays fresh while the
// agent port is disabled; that case returns ErrNoNames.
func (l *Listener) Reload(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ca, err := l.Source.Oldest(ctx)
	if err != nil {
		return err
	}
	if err := l.reloadResponder(ca); err != nil {
		return err
	}
	names, err := l.Names(ctx)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return ErrNoNames
	}
	next := &listenerState{caID: ca.ID, names: slices.Clone(names)}
	cur := l.state.Load()
	if cur != nil && cur.caID == ca.ID && slices.Equal(cur.names, names) &&
		!agentproto.RenewDue(cur.leaf.NotBefore, cur.leaf.NotAfter, l.now()) {
		next.cert, next.leaf = cur.cert, cur.leaf
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		leaf, err := SignServer(ca, &key.PublicKey, names, l.now())
		if err != nil {
			return err
		}
		next.cert = tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}
		next.leaf = leaf
		l.log().Info("agent listener certificate issued", "names", names, "ca", ca.ID, "not_after", leaf.NotAfter)
	}
	l.state.Store(next)
	return nil
}

// TLSConfig serves the listener certificate and requests no client
// certificate. HTTP/2 is not offered: the WebSocket upgrade needs HTTP/1.1.
func (l *Listener) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			st := l.state.Load()
			if st == nil {
				return nil, errors.New("agentca: listener certificate not loaded")
			}
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{st.cert},
				NextProtos: []string{"http/1.1"}}, nil
		},
	}
}

// Info reports the current certificate; false before the first Reload.
func (l *Listener) Info() (ListenerInfo, bool) {
	st := l.state.Load()
	if st == nil {
		return ListenerInfo{}, false
	}
	return ListenerInfo{CAID: st.caID, Names: slices.Clone(st.names), NotAfter: st.leaf.NotAfter}, true
}

// ListenerRenewArgs is the hourly river job that calls Reload.
type ListenerRenewArgs struct{}

// Kind is the river job kind.
func (ListenerRenewArgs) Kind() string { return "certforge_agent_listener_cert" }

// ListenerRenewWorker runs ListenerRenewArgs.
type ListenerRenewWorker struct {
	river.WorkerDefaults[ListenerRenewArgs]
	L *Listener
}

// Work re-checks the listener certificate.
func (w *ListenerRenewWorker) Work(ctx context.Context, _ *river.Job[ListenerRenewArgs]) error {
	if err := w.L.Reload(ctx); err != nil && !errors.Is(err, ErrNoNames) {
		return err
	}
	return nil
}

// RegisterRiver is an issuance.RiverExtra: the worker plus an hourly job.
func (l *Listener) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &ListenerRenewWorker{L: l})
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Hour),
		func() (river.JobArgs, *river.InsertOpts) { return ListenerRenewArgs{}, nil }, nil)}
}
