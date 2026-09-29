package backup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// splitChunks parses data (a chunkWriter's output) into its individual
// length-prefixed records, for tests that need to reorder or drop one.
func splitChunks(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var recs [][]byte
	for len(data) > 0 {
		if len(data) < 4 {
			t.Fatalf("short chunk length prefix: %d bytes left", len(data))
		}
		l := binary.BigEndian.Uint32(data[:4])
		end := 4 + int(l)
		if len(data) < end {
			t.Fatalf("short chunk body: have %d, want %d", len(data), end)
		}
		recs = append(recs, data[:end])
		data = data[end:]
	}
	return recs
}

func joinChunks(recs [][]byte) []byte {
	var out []byte
	for _, r := range recs {
		out = append(out, r...)
	}
	return out
}

// TestChunkStreamRoundTrip covers empty, single-byte, exactly-one-chunk and
// multi-chunk-with-remainder plaintext sizes.
func TestChunkStreamRoundTrip(t *testing.T) {
	key := testKey(1)
	hh := sha256.Sum256([]byte("test-header"))

	for _, n := range []int{0, 1, ChunkSize, 3*ChunkSize + 7} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			plain := make([]byte, n)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			cw, err := newChunkWriter(&buf, key, hh[:])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cw.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err := cw.Close(); err != nil {
				t.Fatal(err)
			}

			cr, err := newChunkReader(&buf, key, hh[:])
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(cr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round trip: got %d bytes, want %d", len(got), len(plain))
			}
		})
	}
}

// TestChunkReorderDetected swaps two whole chunk records; each chunk's AAD
// binds it to its own index, so the swapped chunks fail authentication at
// their new positions instead of silently decrypting out of order.
func TestChunkReorderDetected(t *testing.T) {
	key := testKey(2)
	hh := sha256.Sum256([]byte("test-header"))
	plain := make([]byte, 3*ChunkSize+7)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cw, err := newChunkWriter(&buf, key, hh[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}

	recs := splitChunks(t, buf.Bytes())
	if len(recs) < 2 {
		t.Fatalf("need at least 2 chunks, got %d", len(recs))
	}
	recs[0], recs[1] = recs[1], recs[0]

	cr, err := newChunkReader(bytes.NewReader(joinChunks(recs)), key, hh[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(cr); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

// TestArchiveTruncationDetected covers dropping the true final chunk (the
// stream then ends on a chunk whose AAD says it is not final) and
// appending trailing bytes after a complete, valid stream.
func TestArchiveTruncationDetected(t *testing.T) {
	key := testKey(3)
	hh := sha256.Sum256([]byte("test-header"))
	plain := make([]byte, 3*ChunkSize+7)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	build := func(t *testing.T) []byte {
		t.Helper()
		var buf bytes.Buffer
		cw, err := newChunkWriter(&buf, key, hh[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cw.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := cw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	t.Run("final chunk dropped", func(t *testing.T) {
		recs := splitChunks(t, build(t))
		truncated := joinChunks(recs[:len(recs)-1])
		cr, err := newChunkReader(bytes.NewReader(truncated), key, hh[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(cr); !errors.Is(err, ErrTampered) {
			t.Fatalf("err = %v, want ErrTampered", err)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		data := append(build(t), []byte("trailing garbage bytes")...)
		cr, err := newChunkReader(bytes.NewReader(data), key, hh[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(cr); !errors.Is(err, ErrTampered) {
			t.Fatalf("err = %v, want ErrTampered", err)
		}
	})
}
