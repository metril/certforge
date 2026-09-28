package signer

import "errors"

// ErrNotSupported is returned by a Signer method its kind does not
// implement — for example RenewalInfo on localca and vaultpki, which have
// no ACME ARI to poll.
var ErrNotSupported = errors.New("signer: not supported")
