package render

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Fixed bytes: PEM encoding does not parse DER, so goldens stay stable.
var fixture = Material{
	LeafDER:         []byte("leaf-der-bytes"),
	ChainDER:        [][]byte{[]byte("intermediate-1"), []byte("intermediate-2")},
	PrivateKeyPKCS8: []byte("pkcs8-key-bytes"),
}

func TestPEMGolden(t *testing.T) {
	files, err := Render(fixture, Parts)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(Parts) {
		t.Fatalf("got %d files", len(files))
	}
	for _, f := range files {
		golden := filepath.Join("testdata", f.Name+".golden")
		if *update {
			if err := os.WriteFile(golden, f.Data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run go test ./internal/render -update)", err)
		}
		if !bytes.Equal(f.Data, want) {
			t.Errorf("%s differs from golden", f.Name)
		}
	}
}

func TestRenderRejects(t *testing.T) {
	noKey := fixture
	noKey.PrivateKeyPKCS8 = nil
	if _, err := Render(noKey, []string{"cert", "key"}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("key without material: %v", err)
	}
	if _, err := Render(fixture, []string{"p12"}); err == nil {
		t.Fatal("unknown part accepted")
	}
	if _, err := Render(fixture, nil); err == nil {
		t.Fatal("empty parts accepted")
	}
	files, _ := Render(fixture, []string{"cert", "cert"})
	if len(files) != 1 {
		t.Fatal("duplicate parts not collapsed")
	}
}

func TestZipDeterministicAndReadable(t *testing.T) {
	files, _ := Render(fixture, []string{"fullchain", "key"})
	a, err := Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Zip(files)
	if !bytes.Equal(a, b) {
		t.Fatal("zip not deterministic")
	}
	zr, err := zip.NewReader(bytes.NewReader(a), int64(len(a)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 2 || zr.File[1].Name != "privkey.pem" || zr.File[1].Mode().Perm() != 0o600 {
		t.Fatalf("entries wrong: %v", zr.File)
	}
	rc, _ := zr.File[0].Open()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, files[0].Data) {
		t.Fatal("content mismatch")
	}
}
