package delivery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/render"
)

var material = render.Material{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")}, PrivateKeyPKCS8: []byte("key")}

func okFile(path string) OutputFile {
	return OutputFile{Path: path, Format: "pem", Parts: []string{"fullchain"}, Mode: "0644"}
}

// selfSignedCert returns a real, x509-parseable self-signed certificate:
// the DER/PKCS12/JKS renderers parse their input rather than treating it
// as opaque bytes (unlike material, above, which PEM tests use).
func selfSignedCert(t *testing.T, cn string, serial int64) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: now, NotAfter: now.AddDate(0, 3, 0), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// realMaterial builds render.Material with a real, parseable self-signed
// leaf, one chain cert, and a PKCS#8 key.
func realMaterial(t *testing.T, cn string, serial int64) render.Material {
	t.Helper()
	leafDER, key := selfSignedCert(t, cn, serial)
	chainDER, _ := selfSignedCert(t, "Test Intermediate", serial+1000)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return render.Material{LeafDER: leafDER, ChainDER: [][]byte{chainDER}, PrivateKeyPKCS8: pkcs8}
}

// Review Focus: unsafe paths never reach an agent.
func TestValidateFilesRejectsUnsafePaths(t *testing.T) {
	good := []OutputFile{okFile("/etc/ssl/web/fullchain.pem"),
		{Path: "/etc/ssl/web/key.pem", Format: "pem", Parts: []string{"key"}, Owner: "root", Group: "ssl-cert", Mode: "640"}}
	if err := ValidateFiles(good); err != nil {
		t.Fatal(err)
	}
	many := make([]OutputFile, 21)
	for i := range many {
		many[i] = okFile("/etc/ssl/f" + strings.Repeat("x", i) + ".pem")
	}
	for name, files := range map[string][]OutputFile{
		"none":           nil,
		"too many":       many,
		"relative":       {okFile("etc/ssl/x.pem")},
		"dotdot":         {okFile("/etc/../x.pem")},
		"dot":            {okFile("/etc/./x.pem")},
		"trailing":       {okFile("/etc/ssl/")},
		"root":           {okFile("/")},
		"nul":            {okFile("/etc/x\x00.pem")},
		"duplicate":      {okFile("/etc/x.pem"), okFile("/etc/x.pem")},
		"format":         {{Path: "/etc/x.p7b", Format: "pkcs7", Parts: []string{"cert"}, Mode: "0644"}},
		"no parts":       {{Path: "/etc/x.pem", Format: "pem", Mode: "0644"}},
		"bad part":       {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"pfx"}, Mode: "0644"}},
		"bad mode":       {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert"}, Mode: "0999"}},
		"world-writable": {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert"}, Mode: "0646"}},
		"bad owner":      {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert"}, Owner: "a b", Mode: "0644"}},
		"owner too big":  {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert"}, Owner: "4294967296", Mode: "0644"}},
	} {
		var fe *FieldError
		if err := ValidateFiles(files); !errors.As(err, &fe) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRenderLayoutConcatenatesParts(t *testing.T) {
	l := Layout{Files: []OutputFile{{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert", "key"}, Owner: "root", Mode: "640"}}}
	files, err := RenderLayout(material, nil, l)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := render.PEM{}.Render(material, render.OutputOpts{Parts: []string{"cert", "key"}})
	if len(files) != 1 || !bytes.Equal(files[0].Data, append(append([]byte{}, want[0].Data...), want[1].Data...)) ||
		files[0].Mode != "0640" || files[0].Owner != "root" {
		t.Fatalf("files %+v", files)
	}
	noKey := Layout{Files: []OutputFile{{Path: "/k", Format: "pem", Parts: []string{"key"}, Mode: "0600"}}}
	if _, err := RenderLayout(render.Material{LeafDER: []byte("leaf")}, nil, noKey); !errors.Is(err, render.ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
}

// Review Focus: every ValidateFiles rule for der/p12/jks and encoding/alias.
func TestValidateFilesFormats(t *testing.T) {
	valid := map[string][]OutputFile{
		"pem multi":    {{Path: "/a.pem", Format: "pem", Parts: []string{"cert", "chain"}, Mode: "0644"}},
		"pem extra":    {{Path: "/a.pem", Format: "pem", Parts: []string{"extra"}, Mode: "0644"}},
		"der cert":     {{Path: "/a.der", Format: "der", Parts: []string{"cert"}, Mode: "0644"}},
		"der key":      {{Path: "/a.der", Format: "der", Parts: []string{"key"}, Mode: "0600"}},
		"p12":          {{Path: "/a.p12", Format: "p12", Mode: "0600"}},
		"p12 encoding": {{Path: "/a.p12", Format: "p12", Mode: "0600", Encoding: "legacy"}},
		"jks":          {{Path: "/a.jks", Format: "jks", Mode: "0600"}},
		"jks alias":    {{Path: "/a.jks", Format: "jks", Mode: "0600", Alias: "site-1"}},
	}
	for name, files := range valid {
		if err := ValidateFiles(files); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := map[string][]OutputFile{
		"unknown format":  {{Path: "/a.x", Format: "pkcs7", Mode: "0644"}},
		"pem no parts":    {{Path: "/a.pem", Format: "pem", Mode: "0644"}},
		"der no parts":    {{Path: "/a.der", Format: "der", Mode: "0644"}},
		"der two parts":   {{Path: "/a.der", Format: "der", Parts: []string{"cert", "key"}, Mode: "0644"}},
		"der chain":       {{Path: "/a.der", Format: "der", Parts: []string{"chain"}, Mode: "0644"}},
		"der fullchain":   {{Path: "/a.der", Format: "der", Parts: []string{"fullchain"}, Mode: "0644"}},
		"p12 with parts":  {{Path: "/a.p12", Format: "p12", Parts: []string{"cert"}, Mode: "0600"}},
		"jks with parts":  {{Path: "/a.jks", Format: "jks", Parts: []string{"cert"}, Mode: "0600"}},
		"encoding on pem": {{Path: "/a.pem", Format: "pem", Parts: []string{"cert"}, Mode: "0644", Encoding: "modern"}},
		"encoding on jks": {{Path: "/a.jks", Format: "jks", Mode: "0600", Encoding: "modern"}},
		"bad encoding":    {{Path: "/a.p12", Format: "p12", Mode: "0600", Encoding: "bogus"}},
		"alias on pem":    {{Path: "/a.pem", Format: "pem", Parts: []string{"cert"}, Mode: "0644", Alias: "x"}},
		"alias on p12":    {{Path: "/a.p12", Format: "p12", Mode: "0600", Alias: "x"}},
		"bad alias":       {{Path: "/a.jks", Format: "jks", Mode: "0600", Alias: "bad alias!"}},
	}
	for name, files := range invalid {
		var fe *FieldError
		if err := ValidateFiles(files); !errors.As(err, &fe) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Review Focus: the ledger ruling that keystore randomness must be seeded
// with secret material (the key and password), not public ids alone: two
// renders of the same material/password/path are byte-identical, and a
// changed password changes the bytes.
func TestRenderLayoutKeystoresDeterministic(t *testing.T) {
	m := realMaterial(t, "ks.example.test", 1)
	l := Layout{Files: []OutputFile{{Path: "/etc/x.p12", Format: "p12", Mode: "0600"}}, Password: "hunter2"}
	f1, err := RenderLayout(m, nil, l)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := RenderLayout(m, nil, l)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f1[0].Data, f2[0].Data) {
		t.Fatal("two renders of the same material, password and path differ")
	}
	l2 := l
	l2.Password = "different-pw"
	f3, err := RenderLayout(m, nil, l2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(f1[0].Data, f3[0].Data) {
		t.Fatal("a changed password did not change the rendered bytes")
	}
}

// Review Focus: the PEM extra part is the extra certificates' leaf+chain,
// and a p12 file lists them as CA/trusted certificates.
func TestRenderLayoutExtraPart(t *testing.T) {
	m := realMaterial(t, "main.example.test", 2)
	extraID := uuid.New()
	extra := realMaterial(t, "extra.example.test", 3)
	extras := map[uuid.UUID]render.Material{extraID: extra}

	pemLayout := Layout{Files: []OutputFile{{Path: "/etc/extra.pem", Format: "pem", Parts: []string{"extra"}, Mode: "0644"}},
		ExtraCertIDs: []uuid.UUID{extraID}}
	files, err := RenderLayout(m, extras, pemLayout)
	if err != nil {
		t.Fatal(err)
	}
	want, err := render.PEM{}.Render(m, render.OutputOpts{Parts: []string{"extra"}, Extras: []render.Material{extra}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(files[0].Data, want[0].Data) {
		t.Fatal("extra part does not match render.PEM's own extra rendering")
	}

	p12Layout := Layout{Files: []OutputFile{{Path: "/etc/bundle.p12", Format: "p12", Mode: "0600"}},
		ExtraCertIDs: []uuid.UUID{extraID}, Password: "hunter2"}
	p12Files, err := RenderLayout(m, extras, p12Layout)
	if err != nil {
		t.Fatal(err)
	}
	_, leaf, caCerts, err := pkcs12.DecodeChain(p12Files[0].Data, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.Raw, m.LeafDER) {
		t.Fatal("p12 leaf mismatch")
	}
	found := false
	for _, c := range caCerts {
		if bytes.Equal(c.Raw, extra.LeafDER) {
			found = true
		}
	}
	if !found {
		t.Fatal("p12 does not contain the extra certificate's leaf as a CA cert")
	}
}

func TestNeedsKey(t *testing.T) {
	cases := map[string]struct {
		files []OutputFile
		want  bool
	}{
		"pem cert only": {[]OutputFile{{Format: "pem", Parts: []string{"cert"}}}, false},
		"pem key":       {[]OutputFile{{Format: "pem", Parts: []string{"key"}}}, true},
		"pem combined":  {[]OutputFile{{Format: "pem", Parts: []string{"combined"}}}, true},
		"der cert":      {[]OutputFile{{Format: "der", Parts: []string{"cert"}}}, false},
		"der key":       {[]OutputFile{{Format: "der", Parts: []string{"key"}}}, true},
		"p12":           {[]OutputFile{{Format: "p12"}}, true},
		"jks":           {[]OutputFile{{Format: "jks"}}, true},
		"mixed":         {[]OutputFile{{Format: "pem", Parts: []string{"cert"}}, {Format: "jks"}}, true},
	}
	for name, tc := range cases {
		if got := NeedsKey(tc.files); got != tc.want {
			t.Errorf("%s: NeedsKey = %v, want %v", name, got, tc.want)
		}
	}
}

// Review Focus: certificate names never escape the target directory.
func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"Web Frontend":     "web-frontend",
		"../../etc":        "etc",
		"..":               "cert",
		"api.example.test": "api.example.test",
		"*.example.test":   "example.test",
		"a/b":              "a-b",
	} {
		if got := SafeName(in); got != want || strings.Contains(got, "/") {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTraefik(t *testing.T) {
	if c, err := ParseTraefik(json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)); err != nil || c.Dir != "/etc/traefik/dynamic" {
		t.Fatalf("valid: %+v %v", c, err)
	}
	for name, tc := range map[string]struct{ raw, field string }{
		"unknown":    {`{"dir":"/x","nope":1}`, "config"},
		"relative":   {`{"dir":"etc/traefik"}`, "config.dir"},
		"prefix":     {`{"dir":"/x","pathPrefix":"rel"}`, "config.pathPrefix"},
		"store name": {`{"dir":"/x","stores":["a b"]}`, "config.stores"},
	} {
		var fe *FieldError
		if _, err := ParseTraefik(json.RawMessage(tc.raw)); !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestGrantFilesOrderAndDigests(t *testing.T) {
	files, err := GrantFiles(&material, nil, &Layout{Files: []OutputFile{okFile("/etc/ssl/web.pem")}})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	want := "/etc/ssl/web.pem"
	if strings.Join(paths, ",") != want {
		t.Fatalf("paths %v", paths)
	}
	specs := Specs(files)
	if len(specs) != 1 || len(specs[0].SHA256) != 64 {
		t.Fatalf("specs %+v", specs)
	}

	// m nil (C3: no version yet) renders nothing from the layout.
	if got, err := GrantFiles(nil, nil, &Layout{Files: []OutputFile{okFile("/etc/ssl/web.pem")}}); err != nil || got != nil {
		t.Fatalf("GrantFiles(nil, ...) = %v, %v", got, err)
	}
	// l nil (no layout) also renders nothing.
	if got, err := GrantFiles(&material, nil, nil); err != nil || got != nil {
		t.Fatalf("GrantFiles(m, nil) = %v, %v", got, err)
	}
}

func TestCompare(t *testing.T) {
	expected := []agentproto.FileSpec{{Path: "/a", SHA256: "1"}, {Path: "/b", SHA256: "2"}, {Path: "/c", SHA256: "3"}, {Path: "/d", SHA256: "4"}}
	installed := []agentproto.FileDigest{{Path: "/a", SHA256: "1"}, {Path: "/b", SHA256: "9"}, {Path: "/c", SHA256: ""}, {Path: "/z", SHA256: "0"}}
	missing, mismatched := Compare(expected, installed)
	if strings.Join(missing, ",") != "/c,/d" || strings.Join(mismatched, ",") != "/b" {
		t.Fatalf("missing %v mismatched %v", missing, mismatched)
	}
}

func TestValidateHook(t *testing.T) {
	if err := ValidateHook("post_deploy", []string{"/usr/local/bin/reload-nginx", "--quiet"}, 60); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		phase   string
		argv    []string
		timeout int
	}{
		"phase":    {"post_issue", []string{"/bin/true"}, 60},
		"empty":    {"post_deploy", nil, 60},
		"shell":    {"post_deploy", []string{"sh", "-c", "reload"}, 60},
		"relative": {"post_deploy", []string{"bin/reload"}, 60},
		"timeout":  {"post_deploy", []string{"/bin/true"}, 0},
		"long":     {"post_deploy", []string{"/bin/true"}, 3601},
	} {
		var fe *FieldError
		if err := ValidateHook(tc.phase, tc.argv, tc.timeout); !errors.As(err, &fe) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
