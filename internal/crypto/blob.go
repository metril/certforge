package crypto

import (
	"bytes"
	"encoding/binary"
)

const blobVersion byte = 1

// Blob is one sealed value, stored as a single bytea column via Marshal.
type Blob struct {
	KEKID      string
	WrappedDEK []byte
	Nonce      []byte
	Ciphertext []byte
}

// Marshal encodes b. Lengths produced by Encrypt always fit the header fields.
func (b Blob) Marshal() []byte {
	out := make([]byte, 0, 5+len(b.KEKID)+len(b.WrappedDEK)+len(b.Nonce)+len(b.Ciphertext))
	out = append(out, blobVersion, byte(len(b.KEKID)))
	out = append(out, b.KEKID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.WrappedDEK)))
	out = append(out, b.WrappedDEK...)
	out = append(out, byte(len(b.Nonce)))
	out = append(out, b.Nonce...)
	return append(out, b.Ciphertext...)
}

// Unmarshal decodes data into b, returning ErrMalformedBlob on bad input.
func (b *Blob) Unmarshal(data []byte) error {
	r := data
	if len(r) < 2 || r[0] != blobVersion {
		return ErrMalformedBlob
	}
	n := int(r[1])
	r = r[2:]
	if len(r) < n {
		return ErrMalformedBlob
	}
	kekID := string(r[:n])
	r = r[n:]
	if len(r) < 2 {
		return ErrMalformedBlob
	}
	n = int(binary.BigEndian.Uint16(r))
	r = r[2:]
	if len(r) < n {
		return ErrMalformedBlob
	}
	wrapped := bytes.Clone(r[:n])
	r = r[n:]
	if len(r) < 1 {
		return ErrMalformedBlob
	}
	n = int(r[0])
	r = r[1:]
	if len(r) < n {
		return ErrMalformedBlob
	}
	nonce := bytes.Clone(r[:n])
	r = r[n:]
	if len(r) < 16 {
		return ErrMalformedBlob
	}
	*b = Blob{KEKID: kekID, WrappedDEK: wrapped, Nonce: nonce, Ciphertext: bytes.Clone(r)}
	return nil
}
