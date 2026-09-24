// Package cryptotest provides a reversible, NON-secret crypto.Box for tests.
package cryptotest

import (
	"bytes"
	"context"
	"errors"
)

var prefix = []byte("sealed:")

// PrefixBox marks values as sealed without encrypting them.
type PrefixBox struct{}

func (PrefixBox) Seal(_ context.Context, p []byte) ([]byte, error) {
	return append(append([]byte(nil), prefix...), p...), nil
}

func (PrefixBox) Open(_ context.Context, s []byte) ([]byte, error) {
	if !bytes.HasPrefix(s, prefix) {
		return nil, errors.New("cryptotest: value was not sealed")
	}
	return bytes.Clone(s[len(prefix):]), nil
}
