// Package monitor implements external TLS monitors: polling a host:port on
// a schedule, comparing the presented leaf against an optional expected
// certificate, and raising monitor.mismatch/unreachable/expiring/recovered
// events on a state transition (Shared contracts, Monitor operations row;
// Deviations R5).
package monitor

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/notify/httpx"
)

// ExpiringWithin is how far ahead of a leaf's notAfter the expiring state
// starts (Task 9 brief: "expiring < 14 d").
const ExpiringWithin = 14 * 24 * time.Hour

// DialTimeout bounds a single Observe dial+handshake (Task 9 brief: "dials
// with a 10 s timeout").
const DialTimeout = 10 * time.Second

// InlineTimeout bounds checkMonitor's inline check (Task 9 brief:
// "checkMonitor runs inline bounded 15 s").
const InlineTimeout = 15 * time.Second

// MaxPerOrg is createMonitor's per-org limit (Shared contract: "At most 500
// per org (422)").
const MaxPerOrg = 500

// maxNameLen/maxHostLen/maxSNILen/maxLastLen mirror the migration's own
// CHECK constraints (Shared contract: Monitor.name <= 100, host <= 253,
// sni <= 253, lastIssuer/lastError <= 1000).
const (
	maxNameLen = 100
	maxHostLen = 253
	maxSNILen  = 253
	maxLastLen = 1000
)

// minIntervalSeconds/maxIntervalSeconds are intervalSeconds' bounds (Shared
// contract: "interval_seconds 300-86400").
const (
	minIntervalSeconds = 300
	maxIntervalSeconds = 86400
)

// ErrNotFound means no such monitor in the org.
var ErrNotFound = errors.New("monitor: not found")

// ValidationError is a 422: a bad name, host, sni, port, interval, or an
// expectedCertificateId outside the org.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

// Monitor is a stored external monitor (Shared contract: Monitor schema).
type Monitor struct {
	ID, OrgID               uuid.UUID
	Name, Host              string
	Port                    int
	SNI                     *string
	IntervalSeconds         int
	ExpectedCertID          *uuid.UUID
	ExpectedCertificateName *string
	Enabled                 bool
	State                   string
	StateChangedAt          time.Time
	LastCheckedAt           *time.Time
	NextCheckAt             time.Time
	LastFingerprint         string
	LastNotAfter            *time.Time
	LastIssuer              string
	LastError               string
	ConsecutiveFailures     int
	CreatedAt, UpdatedAt    time.Time
}

// Input is a create or update's resolved fields (Shared contract:
// MonitorInput, defaults already applied by the caller).
type Input struct {
	Name            string
	Host            string
	Port            int
	SNI             *string
	IntervalSeconds int
	ExpectedCertID  *uuid.UUID
	Enabled         bool
}

// ValidateInput cleans and validates in's shape-level fields (name, host
// SSRF policy, sni, port, interval); it does not check expectedCertID
// belongs to the org, which needs a database round trip (the caller's job,
// via Store.CertificateName).
func ValidateInput(in Input, allowLoopback bool) (Input, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxNameLen {
		return Input{}, &ValidationError{Field: "name", Msg: "must be 1 to 100 characters"}
	}
	in.Name = name

	if in.Host == "" || len(in.Host) > maxHostLen {
		return Input{}, &ValidationError{Field: "host", Msg: "must be 1 to 253 characters"}
	}
	if err := httpx.CheckHost(in.Host, allowLoopback); err != nil {
		return Input{}, &ValidationError{Field: "host", Msg: err.Error()}
	}

	if in.SNI != nil {
		sni := strings.TrimSpace(*in.SNI)
		if sni == "" {
			in.SNI = nil
		} else {
			if len(sni) > maxSNILen {
				return Input{}, &ValidationError{Field: "sni", Msg: "must be at most 253 characters"}
			}
			in.SNI = &sni
		}
	}

	if in.Port < 1 || in.Port > 65535 {
		return Input{}, &ValidationError{Field: "port", Msg: "must be 1 to 65535"}
	}

	if in.IntervalSeconds < minIntervalSeconds || in.IntervalSeconds > maxIntervalSeconds {
		return Input{}, &ValidationError{Field: "intervalSeconds", Msg: "must be 300 to 86400"}
	}

	return in, nil
}

// effectiveSNI is what a check sends as TLS ServerName: sni, or host when
// unset (Shared contract: "Sni ... null uses host"; Task 9 brief: "SNI = sni
// or host").
func effectiveSNI(m Monitor) string {
	if m.SNI != nil && *m.SNI != "" {
		return *m.SNI
	}
	return m.Host
}

// ResetsState reports whether changing from cur to in (Input) must reset
// state to unknown and nextCheckAt to now (Shared contract, updateMonitor:
// "Changing host, port, sni or expectedCertificateId resets state").
func ResetsState(cur Monitor, in Input) bool {
	if cur.Host != in.Host || cur.Port != in.Port {
		return true
	}
	curSNI, inSNI := "", ""
	if cur.SNI != nil {
		curSNI = *cur.SNI
	}
	if in.SNI != nil {
		inSNI = *in.SNI
	}
	if curSNI != inSNI {
		return true
	}
	curCert, inCert := uuid.Nil, uuid.Nil
	if cur.ExpectedCertID != nil {
		curCert = *cur.ExpectedCertID
	}
	if in.ExpectedCertID != nil {
		inCert = *in.ExpectedCertID
	}
	return curCert != inCert
}

// truncateUTF8 cuts s to at most maxBytes bytes, trimming back further if
// the cut landed inside a multi-byte rune (same trick as deploy's and
// notify's own truncateUTF8: an incomplete trailing sequence makes Postgres
// reject the string outright, since text columns must be valid UTF-8).
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
