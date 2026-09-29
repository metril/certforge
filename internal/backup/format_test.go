package backup

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// buildArchive assembles a minimal, well-formed archive (magic, header,
// one chunk stream of plaintext) directly from the format's own pieces,
// with no database involved: format_test.go and stream_test.go exercise
// the archive layout itself, independent of Write/Restore.
func buildArchive(t *testing.T, key []byte, h Header, plaintext []byte) (data []byte, chunkOffset int) {
	t.Helper()
	h.Format = Format
	hjson, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	buf.WriteString(Magic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hjson)))
	buf.Write(lenBuf[:])
	buf.Write(hjson)
	chunkOffset = buf.Len()

	hh := headerHash([]byte(Magic), hjson)
	cw, err := newChunkWriter(&buf, key, hh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cw.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), chunkOffset
}

func testHeader() Header {
	return Header{
		CreatedAt:        "2026-01-01T00:00:00Z",
		AppVersion:       "test",
		MigrationVersion: 13,
		ActiveKEKID:      "static-test",
		Tables:           Manifest,
		Salt:             bytes.Repeat([]byte{0x11}, 16),
	}
}

func readArchive(t *testing.T, key, data []byte) ([]byte, error) {
	t.Helper()
	r := bytes.NewReader(data)
	h, hh, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	if h.Format != Format {
		t.Fatalf("unexpected format %q", h.Format)
	}
	cr, err := newChunkReader(r, key, hh)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(cr)
}

// TestArchiveTamperDetected covers a flipped byte inside a chunk's
// ciphertext and inside the plaintext header: both must surface as
// ErrTampered, never as a silent wrong-content decode.
func TestArchiveTamperDetected(t *testing.T) {
	key := testKey(9)
	plain := []byte("hello world, this is the archive's test content")

	t.Run("chunk byte flipped", func(t *testing.T) {
		data, chunkOffset := buildArchive(t, key, testHeader(), plain)
		data[chunkOffset+8] ^= 0xFF // inside the first chunk's ciphertext
		if _, err := readArchive(t, key, data); !errors.Is(err, ErrTampered) {
			t.Fatalf("err = %v, want ErrTampered", err)
		}
	})

	t.Run("header byte flipped", func(t *testing.T) {
		data, chunkOffset := buildArchive(t, key, testHeader(), plain)
		// Somewhere inside the header JSON, well past the length prefix.
		data[len(Magic)+4+len(Magic)] ^= 0xFF
		if chunkOffset <= len(Magic)+4+len(Magic) {
			t.Fatal("test archive's header too short for this offset")
		}
		if _, err := readArchive(t, key, data); !errors.Is(err, ErrTampered) {
			t.Fatalf("err = %v, want ErrTampered", err)
		}
	})
}

func TestReadHeaderBadMagic(t *testing.T) {
	data, _ := buildArchive(t, testKey(1), testHeader(), []byte("x"))
	data[0] = 'X'
	if _, err := ReadHeader(bytes.NewReader(data)); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestReadHeaderTooLarge(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(Magic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], maxHeaderLen+1)
	buf.Write(lenBuf[:])
	if _, err := ReadHeader(&buf); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestReadHeaderMalformedJSON(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(Magic)
	bad := []byte("not json")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(bad)))
	buf.Write(lenBuf[:])
	buf.Write(bad)
	if _, err := ReadHeader(&buf); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestReadHeaderRoundTrip(t *testing.T) {
	h := testHeader()
	data, chunkOffset := buildArchive(t, testKey(1), h, []byte("x"))
	got, err := ReadHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != Format || got.AppVersion != h.AppVersion || got.MigrationVersion != h.MigrationVersion {
		t.Fatalf("got %+v, want format/appVersion/migrationVersion from %+v", got, h)
	}
	if chunkOffset >= len(data) {
		t.Fatal("no chunk data after header")
	}
}
