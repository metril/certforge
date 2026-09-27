package acme

// Preset is a well-known ACME CA offered on the CA screen.
type Preset struct {
	Code         string `json:"preset"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directoryUrl"`
	RequiresEAB  bool   `json:"requiresEab"`
	// Staging is true only for letsencrypt-staging: the one preset whose CA
	// does not itself enforce rate limits. A custom directory (Pebble, or
	// any other staging-like server reached through "custom") is not
	// staging by this signal — the rate-limit ledger enforces it like any
	// production CA, and an e2e run raises the limits through settings
	// instead.
	Staging bool `json:"-"`
}

var presets = []Preset{
	{Code: "letsencrypt", Name: "Let's Encrypt", DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory"},
	{Code: "letsencrypt-staging", Name: "Let's Encrypt (staging)", DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", Staging: true},
	{Code: "zerossl", Name: "ZeroSSL", DirectoryURL: "https://acme.zerossl.com/v2/DV90", RequiresEAB: true},
	{Code: "buypass", Name: "Buypass Go SSL", DirectoryURL: "https://api.buypass.com/acme/directory"},
	{Code: "google", Name: "Google Trust Services", DirectoryURL: "https://dv.acme-v02.api.pki.goog/directory", RequiresEAB: true},
	{Code: "sslcom", Name: "SSL.com", DirectoryURL: "https://acme.ssl.com/sslcom-dv-rsa", RequiresEAB: true},
	{Code: "custom", Name: "Custom directory"},
}

// Presets returns a copy of the preset list in display order.
func Presets() []Preset { return append([]Preset(nil), presets...) }

// PresetByCode finds a preset by its code.
func PresetByCode(code string) (Preset, bool) {
	for _, p := range presets {
		if p.Code == code {
			return p, true
		}
	}
	return Preset{}, false
}
