package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// Restart modes of a pfSense grant.
const (
	PfRestartAll      = "all"
	PfRestartSelected = "selected"
	PfRestartNone     = "none"
)

// pfKeyRe matches every service key pfServices.Keyed can produce.
var pfKeyRe = regexp.MustCompile(`^(webgui|ipsec|openvpn:[a-z]{1,16}:[0-9]{1,9}|captiveportal:[A-Za-z0-9_.-]{1,64}|package:[A-Za-z0-9_.+-]{1,64}|service:[A-Za-z0-9_.-]{1,64})$`)

// PfRestart is a pfSense grant's choice of services to restart.
type PfRestart struct {
	Mode     string   `json:"mode"`
	Services []string `json:"services,omitempty"`
}

// PfSenseService is one service that uses a certificate: a stable key and a
// human label.
type PfSenseService struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

func pfLabelOf(sv pfService) string {
	switch sv.Name {
	case "openvpn":
		l := "OpenVPN"
		if m := pfStr(sv.Extras["vpnmode"]); m != "" {
			l += " " + m
		}
		if id := pfStr(sv.Extras["id"]); id != "" {
			l += " " + id
		}
		return l
	case "ipsec":
		return "IPsec"
	case "captiveportal":
		return "Captive portal zone " + pfStr(sv.Extras["zone"])
	}
	return sv.Name
}

var pfModeRe = regexp.MustCompile(`^[a-z]{1,16}$`)

func pfKeyOf(sv pfService) string {
	switch sv.Name {
	case "openvpn":
		mode := pfStr(sv.Extras["vpnmode"])
		if !pfModeRe.MatchString(mode) {
			mode = "server"
		}
		id := pfStr(sv.Extras["id"])
		if id == "" {
			id = "0"
		}
		return "openvpn:" + mode + ":" + id
	case "ipsec":
		return "ipsec"
	case "captiveportal":
		return "captiveportal:" + pfStr(sv.Extras["zone"])
	}
	return "service:" + sv.Name
}

// Keyed lists the services with their stable keys, WebGUI first.
func (s pfServices) Keyed() []PfSenseService {
	out := []PfSenseService{}
	if s.WebGUI {
		out = append(out, PfSenseService{"webgui", "WebGUI"})
	}
	for _, sv := range s.Services {
		out = append(out, PfSenseService{pfKeyOf(sv), pfLabelOf(sv)})
	}
	for _, p := range s.Packages {
		out = append(out, PfSenseService{"package:" + p, "package " + p})
	}
	return out
}

// onlyKeys returns the services whose key is in keys, and the keys that no
// service reported (in keys' order).
func (s pfServices) onlyKeys(keys []string) (kept pfServices, skipped []string) {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	found := map[string]bool{}
	if s.WebGUI && want["webgui"] {
		kept.WebGUI = true
		found["webgui"] = true
	}
	for _, sv := range s.Services {
		if k := pfKeyOf(sv); want[k] {
			kept.Services = append(kept.Services, sv)
			found[k] = true
		}
	}
	for _, p := range s.Packages {
		if k := "package:" + p; want[k] {
			kept.Packages = append(kept.Packages, p)
			found[k] = true
		}
	}
	for _, k := range keys {
		if !found[k] {
			skipped = append(skipped, k)
		}
	}
	return kept, skipped
}

// MarshalJSON encodes the structure cert_restart_services expects; extras
// are always an object so PHP decodes them as an array.
func (s pfServices) MarshalJSON() ([]byte, error) {
	svcs := make([]map[string]any, 0, len(s.Services))
	for _, sv := range s.Services {
		extras := sv.Extras
		if extras == nil {
			extras = map[string]any{}
		}
		svcs = append(svcs, map[string]any{"name": sv.Name, "extras": extras})
	}
	pk := s.Packages
	if pk == nil {
		pk = []string{}
	}
	return json.Marshal(map[string]any{"webgui": s.WebGUI, "services": svcs, "packages": pk})
}

// restartSelected restarts only the services of the certificate whose key is
// in keys. It reads the current list first, filters in Go and hands the
// filtered structure back as base64 JSON, so no selected key reaches PHP
// source. It returns what it restarted and the keys that no longer use the
// certificate.
func (n *nexusClient) restartSelected(ctx context.Context, refid string, keys []string) (pfServices, []string, error) {
	var none pfServices
	cur, err := n.CertServices(ctx, refid)
	if err != nil {
		return none, nil, err
	}
	kept, skipped := cur.onlyKeys(keys)
	if len(kept.Keyed()) == 0 {
		return kept, skipped, nil
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return none, nil, err
	}
	code := `require_once("certs.inc"); $s = json_decode(base64_decode("` + base64.StdEncoding.EncodeToString(b) +
		`"), true); cert_restart_services($s); echo "` + pfMarker + `" . json_encode($s);`
	if _, err := n.phpMarked(ctx, code); err != nil {
		return none, nil, err
	}
	return kept, skipped, nil
}

func pfSkippedNote(skipped []string) string {
	if len(skipped) == 0 {
		return ""
	}
	return "; skipped, no longer in use: " + strings.Join(skipped, ", ")
}
