package targets

import (
	"encoding/pem"
	"fmt"

	"github.com/metril/certforge/internal/render"
)

// MaterialFromPEM parses a leaf+chain "fullchain" PEM (one or more
// CERTIFICATE blocks, the first the leaf, the rest the chain in order) and
// a PKCS#8 "PRIVATE KEY" PEM into render.Material, the canonical form
// Target.Deploy and FileTarget.Files render from — used wherever a target
// receives PEM directly (an agent reporting material back to a server-side
// target, a test) rather than already-decoded DER.
func MaterialFromPEM(fullchain, key []byte) (*render.Material, error) {
	var leaf []byte
	var chain [][]byte
	rest := fullchain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if leaf == nil {
			leaf = block.Bytes
			continue
		}
		chain = append(chain, block.Bytes)
	}
	if leaf == nil {
		return nil, fmt.Errorf("targets: no CERTIFICATE block in fullchain PEM")
	}
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("targets: no PKCS#8 PRIVATE KEY block")
	}
	return &render.Material{LeafDER: leaf, ChainDER: chain, PrivateKeyPKCS8: keyBlock.Bytes}, nil
}
