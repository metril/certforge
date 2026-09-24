package acme

// Preset is a well-known ACME CA offered on the CA screen.
type Preset struct {
	Code         string `json:"preset"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directoryUrl"`
	RequiresEAB  bool   `json:"requiresEab"`
}

var presets = []Preset{
	{"letsencrypt", "Let's Encrypt", "https://acme-v02.api.letsencrypt.org/directory", false},
	{"letsencrypt-staging", "Let's Encrypt (staging)", "https://acme-staging-v02.api.letsencrypt.org/directory", false},
	{"zerossl", "ZeroSSL", "https://acme.zerossl.com/v2/DV90", true},
	{"buypass", "Buypass Go SSL", "https://api.buypass.com/acme/directory", false},
	{"google", "Google Trust Services", "https://dv.acme-v02.api.pki.goog/directory", true},
	{"sslcom", "SSL.com", "https://acme.ssl.com/sslcom-dv-rsa", true},
	{"custom", "Custom directory", "", false},
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
