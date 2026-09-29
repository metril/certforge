package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// headerHash returns sha256(magic‖headerJSON), the chunk stream's AAD root.
func headerHash(magic, headerJSON []byte) []byte {
	h := sha256.New()
	h.Write(magic)
	h.Write(headerJSON)
	return h.Sum(nil)
}

// newAEAD returns an AES-256-GCM cipher for a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("backup: stream key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// chunkNonce is 4 zero bytes followed by index, big-endian: unique per
// chunk within one archive without needing a random draw per chunk, since
// index never repeats within a stream encrypted under one key.
func chunkNonce(index uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], index)
	return nonce
}

// chunkAAD binds a chunk's ciphertext to the archive's header, its position
// and whether it is the last chunk, so flipping a header byte, dropping the
// final chunk or reordering chunks all fail authentication instead of
// silently decrypting.
func chunkAAD(headerHash []byte, index uint64, final bool) []byte {
	aad := make([]byte, 0, len(headerHash)+9)
	aad = append(aad, headerHash...)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	aad = append(aad, idx[:]...)
	if final {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	return aad
}

// chunkWriter encrypts plaintext written to it into AES-256-GCM chunks of
// at most ChunkSize bytes, each length-prefixed (uint32 BE) onto the
// underlying writer. Close flushes the final chunk — always at least one
// chunk is written, even for zero bytes of plaintext — marked final in its
// AAD so a reader can tell where the stream legitimately ends.
type chunkWriter struct {
	w          io.Writer
	aead       cipher.AEAD
	headerHash []byte
	buf        []byte
	index      uint64
	closed     bool
}

func newChunkWriter(w io.Writer, key, headerHash []byte) (*chunkWriter, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &chunkWriter{w: w, aead: aead, headerHash: headerHash, buf: make([]byte, 0, ChunkSize)}, nil
}

// Write implements io.Writer.
func (c *chunkWriter) Write(p []byte) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("backup: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		room := ChunkSize - len(c.buf)
		take := room
		if take > len(p) {
			take = len(p)
		}
		c.buf = append(c.buf, p[:take]...)
		p = p[take:]
		if len(c.buf) == ChunkSize {
			if err := c.flush(false); err != nil {
				return total - len(p), err
			}
		}
	}
	return total, nil
}

// flush seals c.buf as the chunk at c.index and writes it, length-prefixed.
func (c *chunkWriter) flush(final bool) error {
	aad := chunkAAD(c.headerHash, c.index, final)
	nonce := chunkNonce(c.index)
	ct := c.aead.Seal(nil, nonce, c.buf, aad)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := c.w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(ct); err != nil {
		return err
	}
	c.index++
	c.buf = c.buf[:0]
	return nil
}

// Close flushes the final (possibly empty) chunk. It is safe to call once;
// a second call is a no-op.
func (c *chunkWriter) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.flush(true)
}

// rawChunk is one length-prefixed ciphertext chunk, not yet decrypted.
type rawChunk struct {
	ct []byte
}

// maxChunkCiphertext bounds a chunk's declared ciphertext length: at most
// ChunkSize bytes of plaintext plus the GCM tag, with a small margin. A
// length prefix above this is already known to be invalid — rejected
// before it can make readRawChunk allocate an attacker-chosen amount of
// memory from a handful of untrusted bytes.
const maxChunkCiphertext = ChunkSize + 64

// readRawChunk reads one length-prefixed chunk from r. A clean end of
// stream (no bytes at all) reports io.EOF; anything else short of a full
// chunk, or a declared length above maxChunkCiphertext, is ErrTampered.
func readRawChunk(r io.Reader) (*rawChunk, error) {
	var lenBuf [4]byte
	n, err := io.ReadFull(r, lenBuf[:])
	if err != nil {
		if err == io.EOF && n == 0 { //nolint:errorlint // io.ReadFull documents this exact sentinel/count pairing for a clean EOF
			return nil, io.EOF
		}
		return nil, fmt.Errorf("%w: chunk length: %w", ErrTampered, err)
	}
	l := binary.BigEndian.Uint32(lenBuf[:])
	if l > maxChunkCiphertext {
		return nil, fmt.Errorf("%w: chunk length %d exceeds %d", ErrTampered, l, maxChunkCiphertext)
	}
	ct := make([]byte, l)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, fmt.Errorf("%w: chunk body: %w", ErrTampered, err)
	}
	return &rawChunk{ct: ct}, nil
}

// chunkReader decrypts a chunkWriter's stream. Because a chunk's AAD
// depends on whether it is final, chunkReader looks one raw chunk ahead
// before decrypting the current one: if there is no next chunk, the
// current one must be final; if there is, it must not be. A dropped final
// chunk, trailing garbage or a reordered chunk all then fail GCM
// authentication instead of silently decrypting with the wrong AAD
// (TestArchiveTruncationDetected, TestChunkReorderDetected).
type chunkReader struct {
	r          io.Reader
	aead       cipher.AEAD
	headerHash []byte
	index      uint64
	lookahead  *rawChunk
	pending    []byte
	done       bool
}

func newChunkReader(r io.Reader, key, headerHash []byte) (*chunkReader, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &chunkReader{r: r, aead: aead, headerHash: headerHash}, nil
}

// nextChunk returns the next chunk's ciphertext and whether it is final.
func (c *chunkReader) nextChunk() ([]byte, bool, error) {
	if c.done {
		return nil, false, io.EOF
	}
	cur := c.lookahead
	c.lookahead = nil
	if cur == nil {
		var err error
		cur, err = readRawChunk(c.r)
		if err == io.EOF { //nolint:errorlint // readRawChunk documents this exact sentinel for "no chunks at all"
			// A well-formed stream always has at least the final chunk
			// (chunkWriter.Close always flushes one); an entirely absent
			// stream is itself tampering, not an empty archive.
			c.done = true
			return nil, false, fmt.Errorf("%w: no chunks", ErrTampered)
		}
		if err != nil {
			return nil, false, err
		}
	}
	next, err := readRawChunk(c.r)
	if err == io.EOF { //nolint:errorlint // readRawChunk documents this exact sentinel for "no chunks at all"
		c.done = true
		return cur.ct, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	c.lookahead = next
	return cur.ct, false, nil
}

// Read implements io.Reader.
func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.done {
			return 0, io.EOF
		}
		ct, final, err := c.nextChunk()
		if err != nil {
			return 0, err
		}
		aad := chunkAAD(c.headerHash, c.index, final)
		nonce := chunkNonce(c.index)
		pt, err := c.aead.Open(nil, nonce, ct, aad)
		if err != nil {
			return 0, ErrTampered
		}
		c.index++
		c.pending = pt
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
