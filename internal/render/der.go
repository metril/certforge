package render

import (
	"errors"
	"fmt"
)

const derType = "application/octet-stream"

// DER renders individual DER-encoded files. Only cert, key and chain are
// available in DER form; fullchain and combined mix multiple PEM blocks
// into one PEM file, which DER cannot represent.
type DER struct{}

// Format returns the renderer's format name.
func (DER) Format() string { return "der" }

// Render renders the requested parts as DER files.
func (DER) Render(m Material, opts OutputOpts) ([]File, error) {
	if len(opts.Parts) == 0 {
		return nil, errors.New("no parts requested")
	}
	seen := map[string]bool{}
	var out []File
	for _, p := range opts.Parts {
		if seen[p] {
			continue
		}
		seen[p] = true
		switch p {
		case "cert":
			out = append(out, File{Name: "cert.der", ContentType: derType, Data: m.LeafDER})
		case "key":
			if len(m.PrivateKeyPKCS8) == 0 {
				return nil, ErrNoKey
			}
			out = append(out, File{Name: "privkey.der", ContentType: derType, Data: m.PrivateKeyPKCS8, Secret: true})
		case "chain":
			for i, c := range m.ChainDER {
				out = append(out, File{Name: fmt.Sprintf("chain-%d.der", i+1), ContentType: derType, Data: c})
			}
		case "fullchain", "combined":
			return nil, ErrNotDER
		default:
			return nil, fmt.Errorf("unknown part %q", p)
		}
	}
	return out, nil
}
