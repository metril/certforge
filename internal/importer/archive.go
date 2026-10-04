package importer

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"testing/fstest"
)

// ErrArchive means r is not a zip or gzip stream, or violates one of
// ExtractArchive's guards (too many entries, too much uncompressed data, an
// absolute or ".." path). Every error ExtractArchive returns wraps it, so
// callers can tell an archive problem (422) apart from any other failure.
var ErrArchive = errors.New("invalid or oversized archive")

const (
	maxEntries           = 2000
	maxUncompressedBytes = 128 << 20 // 128 MiB
)

// zipMagic and gzipMagic are the byte sequences ExtractArchive sniffs to
// tell a zip archive from a gzip-compressed tar apart from anything else.
var (
	zipMagic  = [][]byte{{'P', 'K', 0x03, 0x04}, {'P', 'K', 0x05, 0x06}, {'P', 'K', 0x07, 0x08}}
	gzipMagic = []byte{0x1f, 0x8b}
)

// ExtractArchive sniffs r as a zip or gzip-compressed tar stream (anything
// else is ErrArchive) and extracts it into an in-memory fs.FS. Every entry
// is checked while it streams, never trusting the archive's own size
// fields: more than 2,000 entries, more than 128 MiB of uncompressed data
// in total, or any entry whose path is absolute or contains a ".."
// component (zip-slip) fails the whole extraction. An entry that is not a
// regular file (a directory, a symlink, or anything else) is silently
// skipped rather than extracted.
func ExtractArchive(r io.Reader) (fs.FS, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	switch {
	case hasAnyPrefix(magic, zipMagic):
		return extractZip(br)
	case bytes.HasPrefix(magic, gzipMagic):
		return extractTarGz(br)
	default:
		return nil, ErrArchive
	}
}

func hasAnyPrefix(b []byte, prefixes [][]byte) bool {
	for _, p := range prefixes {
		if bytes.HasPrefix(b, p) {
			return true
		}
	}
	return false
}

func extractZip(r io.Reader) (fs.FS, error) {
	// zip.NewReader needs an io.ReaderAt over the whole stream; the caller
	// (requireJSON's 32 MiB MaxBytesReader) already bounds how much this
	// can ever read.
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	out := fstest.MapFS{}
	var entries, total int64
	for _, f := range zr.File {
		entries++
		if entries > maxEntries {
			return nil, fmt.Errorf("%w: more than %d entries", ErrArchive, maxEntries)
		}
		name, ok := safeArchivePath(f.Name)
		if !ok {
			return nil, fmt.Errorf("%w: unsafe path %q", ErrArchive, f.Name)
		}
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrArchive, err)
		}
		data, n, err := readWithinBudget(rc, maxUncompressedBytes-total)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		total += n
		out[name] = &fstest.MapFile{Data: data, Mode: 0o644}
	}
	return out, nil
}

func extractTarGz(r io.Reader) (fs.FS, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	defer func() { _ = gz.Close() }()
	// Count every inflated byte, including data tar skips inside non-regular
	// entries, which readWithinBudget never sees.
	tr := tar.NewReader(&budgetReader{r: gz, remaining: maxUncompressedBytes})
	out := fstest.MapFS{}
	var entries, total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrArchive, err)
		}
		entries++
		if entries > maxEntries {
			return nil, fmt.Errorf("%w: more than %d entries", ErrArchive, maxEntries)
		}
		name, ok := safeArchivePath(hdr.Name)
		if !ok {
			return nil, fmt.Errorf("%w: unsafe path %q", ErrArchive, hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			// Directories, symlinks, hard links, devices, ... — never
			// extracted. Any data tr.Next() inflates to skip one still
			// counts against maxUncompressedBytes via budgetReader.
			continue
		}
		data, n, err := readWithinBudget(tr, maxUncompressedBytes-total)
		if err != nil {
			return nil, err
		}
		total += n
		out[name] = &fstest.MapFile{Data: data, Mode: 0o644}
	}
	return out, nil
}

// readWithinBudget reads all of r, failing (ErrArchive) the instant more
// than remaining bytes come out of it — the actual decompressed byte count,
// never a header's own claimed size, is what is compared against the
// budget, so a header that understates its size cannot smuggle a
// decompression bomb past the check.
func readWithinBudget(r io.Reader, remaining int64) (data []byte, n int64, err error) {
	if remaining < 0 {
		remaining = 0
	}
	data, err = io.ReadAll(io.LimitReader(r, remaining+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	if int64(len(data)) > remaining {
		return nil, 0, fmt.Errorf("%w: more than %d bytes uncompressed", ErrArchive, maxUncompressedBytes)
	}
	return data, int64(len(data)), nil
}

// safeArchivePath rejects an absolute path or one with a ".." component
// (zip-slip) and otherwise returns the cleaned, slash-separated path
// fstest.MapFS expects as a key.
func safeArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, `\`, "/")
	if name == "" || path.IsAbs(name) {
		return "", false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", false
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", false
	}
	return cleaned, true
}

// budgetReader errors (ErrArchive) once more than remaining bytes have been
// read through it. Unlike io.LimitReader it fails loudly instead of
// returning a silent EOF that tar would treat as a truncated archive.
type budgetReader struct {
	r         io.Reader
	remaining int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, fmt.Errorf("%w: more than %d bytes uncompressed", ErrArchive, maxUncompressedBytes)
	}
	// Read at most one byte past the budget so overflow is detected exactly.
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, fmt.Errorf("%w: more than %d bytes uncompressed", ErrArchive, maxUncompressedBytes)
	}
	return n, err
}
