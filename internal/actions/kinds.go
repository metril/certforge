// Package actions defines the action kinds a grant's steps can run (exec,
// restart, ssh, http, ...), their config schemas and validation, and the
// expansion of a grant's step list into an ordered list of actions.
package actions

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
)

//go:embed schemas/*.json
var schemaFS embed.FS

// Config is a parsed action config: Public is stored as is; Secrets are the
// schema's secret fields, to be sealed. A secret field that is not a string
// (http secretHeaders) is held as its JSON encoding.
type Config struct {
	Public  json.RawMessage
	Secrets map[string]string
}

// Kind is one action type.
type Kind interface {
	Code() string
	Name() string
	// RunsOn says where the action runs: Agent for exec and restart, Server otherwise.
	RunsOn() targets.Mode
	Schema() json.RawMessage
	// TargetTypes lists the deploy target types a targetId may refer to; empty
	// when the kind has no targetId.
	TargetTypes() []string
	// PhaseHint is the phase the UI suggests: "post_deploy", or "" for none.
	PhaseHint() string
	// Parse validates a config and splits it into public and secret parts.
	Parse(raw json.RawMessage) (Config, error)
}

type kind struct {
	code, name, hint string
	runsOn           targets.Mode
	types            []string
	schema           json.RawMessage
	secrets          []string
	validate         func(m map[string]json.RawMessage, raw json.RawMessage) error
}

func (k *kind) Code() string            { return k.code }
func (k *kind) Name() string            { return k.name }
func (k *kind) RunsOn() targets.Mode    { return k.runsOn }
func (k *kind) Schema() json.RawMessage { return k.schema }
func (k *kind) TargetTypes() []string   { return k.types }
func (k *kind) PhaseHint() string       { return k.hint }

func (k *kind) Parse(raw json.RawMessage) (Config, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return Config{}, &delivery.FieldError{Field: "config", Msg: "must be a JSON object"}
	}
	if err := k.validate(m, raw); err != nil {
		return Config{}, err
	}
	secrets := map[string]string{}
	for _, s := range k.secrets {
		v, ok := m[s]
		if !ok {
			continue
		}
		delete(m, s)
		var str string
		if json.Unmarshal(v, &str) == nil {
			if str != "" {
				secrets[s] = str
			}
			continue
		}
		if t := bytes.TrimSpace(v); string(t) != "null" && string(t) != "{}" {
			secrets[s] = string(t)
		}
	}
	pub, err := json.Marshal(m)
	if err != nil {
		return Config{}, err
	}
	return Config{Public: pub, Secrets: secrets}, nil
}

// Registry holds the action kinds by code.
type Registry struct {
	mu    sync.RWMutex
	kinds map[string]Kind
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{kinds: map[string]Kind{}} }

// Register adds k; it panics on a duplicate code.
func (r *Registry) Register(k Kind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.kinds[k.Code()]; dup {
		panic("actions: duplicate kind " + k.Code())
	}
	r.kinds[k.Code()] = k
}

// Get returns the kind with code.
func (r *Registry) Get(code string) (Kind, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.kinds[code]
	return k, ok
}

// All returns every kind sorted by code.
func (r *Registry) All() []Kind {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Kind, 0, len(r.kinds))
	for _, k := range r.kinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code() < out[j].Code() })
	return out
}

// Default holds the built-in kinds.
var Default = newDefault()

// pfKeyRe duplicates deploy.pfKeyRe (internal/deploy/pfsense_restart.go),
// which this package cannot import; keep the two in sync.
var pfKeyRe = regexp.MustCompile(`^(webgui|ipsec|openvpn:[a-z]{1,16}:[0-9]{1,9}|captiveportal:[A-Za-z0-9_.-]{1,64}|package:[A-Za-z0-9_.+-]{1,64}|service:[A-Za-z0-9_.-]{1,64})$`)

func fe(field, msg string) error { return &delivery.FieldError{Field: field, Msg: msg} }

// decode strictly decodes raw (unknown fields are an error) into v.
func decode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fe("config", err.Error())
	}
	return nil
}

func checkUUID(field, s string) error {
	if _, err := uuid.Parse(s); err != nil {
		return fe(field, "must be a UUID")
	}
	return nil
}

func checkCommand(c string) error {
	if c == "" || len(c) > 512 || strings.ContainsRune(c, 0) {
		return fe("command", "command is 1 to 512 characters without NUL")
	}
	return nil
}

var headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func checkHeaders(field string, h map[string]string) error {
	for k, v := range h {
		if !headerNameRE.MatchString(k) || len(k) > 128 {
			return fe(field, fmt.Sprintf("invalid header name %q", k))
		}
		if len(v) > 2048 || strings.ContainsAny(v, "\r\n\x00") {
			return fe(field, fmt.Sprintf("invalid value for header %q", k))
		}
	}
	return nil
}

func newDefault() *Registry {
	r := NewRegistry()
	load := func(code string) json.RawMessage {
		b, err := schemaFS.ReadFile("schemas/" + code + ".json")
		if err != nil {
			panic(err)
		}
		return b
	}
	add := func(code, name, hint string, runsOn targets.Mode, types []string, secrets []string,
		validate func(m map[string]json.RawMessage, raw json.RawMessage) error) {
		r.Register(&kind{code: code, name: name, hint: hint, runsOn: runsOn, types: types,
			schema: load(code), secrets: secrets, validate: validate})
	}
	const post = "post_deploy"

	add("exec", "Run command", "", targets.Agent, nil, nil, func(_ map[string]json.RawMessage, raw json.RawMessage) error {
		var c struct {
			Argv []string `json:"argv"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		return delivery.ValidateHook("exec", "post_deploy", "", c.Argv, 1)
	})
	add("restart", "Restart service", "", targets.Agent, nil, nil, func(_ map[string]json.RawMessage, raw json.RawMessage) error {
		var c struct {
			Target string `json:"target"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		return delivery.ValidateHook("restart", "post_deploy", c.Target, nil, 1)
	})
	targetCmd := func(raw json.RawMessage) error {
		var c struct {
			TargetID string `json:"targetId"`
			Command  string `json:"command"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		if err := checkUUID("targetId", c.TargetID); err != nil {
			return err
		}
		return checkCommand(c.Command)
	}
	targetOnly := func(raw json.RawMessage) error {
		var c struct {
			TargetID string `json:"targetId"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		return checkUUID("targetId", c.TargetID)
	}
	add("ssh", "SSH command", post, targets.Server, []string{"ssh", "pikvm"}, nil,
		func(_ map[string]json.RawMessage, raw json.RawMessage) error { return targetCmd(raw) })
	add("pfsense_shell", "pfSense shell command", post, targets.Server, []string{"pfsense"}, nil,
		func(_ map[string]json.RawMessage, raw json.RawMessage) error { return targetCmd(raw) })
	add("pfsense_restart", "Restart pfSense services", post, targets.Server, []string{"pfsense"}, nil,
		func(_ map[string]json.RawMessage, raw json.RawMessage) error {
			var c struct {
				TargetID string   `json:"targetId"`
				Mode     string   `json:"mode"`
				Services []string `json:"services"`
			}
			if err := decode(raw, &c); err != nil {
				return err
			}
			if err := checkUUID("targetId", c.TargetID); err != nil {
				return err
			}
			switch c.Mode {
			case "", "all", "none":
				if len(c.Services) > 0 {
					return fe("services", "only allowed when mode is selected")
				}
			case "selected":
				if len(c.Services) == 0 {
					return fe("services", "select at least one service")
				}
				if len(c.Services) > 64 {
					return fe("services", "at most 64 services")
				}
				seen := map[string]bool{}
				for _, k := range c.Services {
					if !pfKeyRe.MatchString(k) {
						return fe("services", fmt.Sprintf("invalid service key %q", k))
					}
					if seen[k] {
						return fe("services", fmt.Sprintf("duplicate service key %q", k))
					}
					seen[k] = true
				}
			default:
				return fe("mode", "mode must be all, selected or none")
			}
			return nil
		})
	add("truenas_restart", "Restart TrueNAS services", post, targets.Server, []string{"truenas"}, nil,
		func(_ map[string]json.RawMessage, raw json.RawMessage) error { return targetOnly(raw) })
	add("routeros_restart", "Restart RouterOS services", post, targets.Server, []string{"routeros"}, nil,
		func(_ map[string]json.RawMessage, raw json.RawMessage) error { return targetOnly(raw) })
	add("http", "HTTP request", post, targets.Server, nil, []string{"secretHeaders"},
		func(_ map[string]json.RawMessage, raw json.RawMessage) error {
			var c struct {
				Method        string            `json:"method"`
				URL           string            `json:"url"`
				Headers       map[string]string `json:"headers"`
				SecretHeaders map[string]string `json:"secretHeaders"`
				Body          string            `json:"body"`
				Expected      *struct {
					Min int `json:"min"`
					Max int `json:"max"`
				} `json:"expectedStatus"`
			}
			if err := decode(raw, &c); err != nil {
				return err
			}
			switch c.Method {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
			default:
				return fe("method", "method must be GET, POST, PUT, PATCH or DELETE")
			}
			u, err := url.Parse(c.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(c.URL) > 2048 {
				return fe("url", "must be an http or https URL")
			}
			if err := checkHeaders("headers", c.Headers); err != nil {
				return err
			}
			if err := checkHeaders("secretHeaders", c.SecretHeaders); err != nil {
				return err
			}
			if len(c.Body) > 8192 {
				return fe("body", "body is at most 8192 bytes")
			}
			if e := c.Expected; e != nil && (e.Min < 100 || e.Max > 599 || e.Min > e.Max) {
				return fe("expectedStatus", "must be a range within 100 to 599, min not above max")
			}
			return nil
		})
	add("notify", "Send notification", post, targets.Server, nil, nil, func(_ map[string]json.RawMessage, raw json.RawMessage) error {
		var c struct {
			ChannelID string `json:"channelId"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		return checkUUID("channelId", c.ChannelID)
	})
	add("verify_tls", "Verify TLS", post, targets.Server, nil, nil, func(_ map[string]json.RawMessage, raw json.RawMessage) error {
		var c struct {
			Host string `json:"host"`
			Port *int   `json:"port"`
			SNI  string `json:"sni"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		if c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/ \x00") {
			return fe("host", "host is a hostname or IP address")
		}
		if c.Port != nil && (*c.Port < 1 || *c.Port > 65535) {
			return fe("port", "port is 1 to 65535")
		}
		if len(c.SNI) > 253 {
			return fe("sni", "server name is at most 253 characters")
		}
		return nil
	})
	add("wait", "Wait", "", targets.Server, nil, nil, func(_ map[string]json.RawMessage, raw json.RawMessage) error {
		var c struct {
			Seconds int `json:"seconds"`
		}
		if err := decode(raw, &c); err != nil {
			return err
		}
		if c.Seconds < 1 || c.Seconds > 300 {
			return fe("seconds", "seconds is 1 to 300")
		}
		return nil
	})
	return r
}

// ValidateOptional rejects optional for a kind that runs on an agent: the
// agent's hook spec has no optional flag, so a failure there always counts.
func ValidateOptional(k Kind, optional bool) error {
	if optional && k.RunsOn() == targets.Agent {
		return &delivery.FieldError{Field: "optional", Msg: "agent-run actions cannot be optional"}
	}
	return nil
}
