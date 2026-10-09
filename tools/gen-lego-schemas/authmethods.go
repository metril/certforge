package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// authMethod is one complete way to authenticate a provider: the user
// supplies every field in Fields (all required). Optional lists further
// credential-group fields that refine the method but are not required.
type authMethod struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Fields   []string `json:"fields"`
	Optional []string `json:"optional"`
}

// authOverrides hand-curates the methods of providers whose constructors
// cannot be derived from env.Get calls (SDK-backed credential chains, no
// env.Get, or shut-down providers). Keyed by provider code. Every field named
// here must exist in the provider's schema and must not be a serverPath one.
var authOverrides = map[string][]authMethod{
	"azure": {
		{ID: "client-secret", Label: "Client secret", Fields: []string{"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP"}, Optional: []string{"AZURE_ENVIRONMENT"}},
		{ID: "ambient", Label: ambientLabel, Fields: []string{}, Optional: []string{"AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "AZURE_ENVIRONMENT"}},
	},
	"azuredns": {
		{ID: "client-secret", Label: "Client secret", Fields: []string{"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"}, Optional: []string{}},
		{ID: "ambient", Label: ambientLabel, Fields: []string{}, Optional: []string{}},
	},
	"cloudxns": {
		{ID: "api-key", Label: "API key + secret key", Fields: []string{"CLOUDXNS_API_KEY", "CLOUDXNS_SECRET_KEY"}, Optional: []string{}},
	},
	"hetzner": {
		{ID: "api-token", Label: "API token", Fields: []string{"HETZNER_API_TOKEN"}, Optional: []string{}},
	},
	"rfc2136": {
		{ID: "tsig", Label: "Nameserver (optional TSIG)", Fields: []string{"RFC2136_NAMESERVER"}, Optional: []string{"RFC2136_TSIG_KEY", "RFC2136_TSIG_SECRET", "RFC2136_TSIG_ALGORITHM"}},
	},
	"designate": {
		{ID: "password", Label: "Username + password", Fields: []string{"OS_AUTH_URL", "OS_USERNAME", "OS_PASSWORD"}, Optional: []string{"OS_USER_ID", "OS_PROJECT_NAME", "OS_REGION_NAME"}},
		{ID: "app-credential", Label: "Application credential", Fields: []string{"OS_AUTH_URL", "OS_APPLICATION_CREDENTIAL_ID", "OS_APPLICATION_CREDENTIAL_SECRET"}, Optional: []string{"OS_APPLICATION_CREDENTIAL_NAME", "OS_USER_ID", "OS_REGION_NAME"}},
	},
	"dnsimple": {
		{ID: "oauth-token", Label: "OAuth token", Fields: []string{"DNSIMPLE_OAUTH_TOKEN"}, Optional: []string{}},
	},
	"edgedns": {
		{ID: "edgegrid", Label: "EdgeGrid credentials", Fields: []string{"AKAMAI_HOST", "AKAMAI_CLIENT_TOKEN", "AKAMAI_CLIENT_SECRET", "AKAMAI_ACCESS_TOKEN"}, Optional: []string{}},
	},
	"gandiv5": {
		{ID: "personal-access-token", Label: "Personal access token", Fields: []string{"GANDIV5_PERSONAL_ACCESS_TOKEN"}, Optional: []string{}},
		{ID: "api-key", Label: "API key (deprecated)", Fields: []string{"GANDIV5_API_KEY"}, Optional: []string{}},
	},
	"gcloud": {
		{ID: "service-account", Label: "Service account key", Fields: []string{"GCE_SERVICE_ACCOUNT"}, Optional: []string{"GCE_PROJECT"}},
		{ID: "ambient", Label: ambientLabel, Fields: []string{}, Optional: []string{"GCE_PROJECT"}},
	},
	"googledomains": {
		{ID: "access-token", Label: "Access token", Fields: []string{"GOOGLE_DOMAINS_ACCESS_TOKEN"}, Optional: []string{}},
	},
	"hyperone": {
		{ID: "passport", Label: "Passport", Fields: []string{"HYPERONE_PASSPORT"}, Optional: []string{}},
	},
	"joker": {
		{ID: "username-password", Label: "Username + password", Fields: []string{"JOKER_USERNAME", "JOKER_PASSWORD"}, Optional: []string{"JOKER_API_MODE"}},
		{ID: "api-key", Label: "API key", Fields: []string{"JOKER_API_KEY"}, Optional: []string{"JOKER_API_MODE"}},
	},
	"lightsail": {
		{ID: "access-key", Label: "Access key", Fields: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}, Optional: []string{"DNS_ZONE"}},
		{ID: "ambient", Label: ambientLabel, Fields: []string{}, Optional: []string{"DNS_ZONE"}},
	},
	"ovh": {
		{ID: "app-key", Label: "Application key", Fields: []string{"OVH_ENDPOINT", "OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY"}, Optional: []string{}},
		{ID: "oauth2", Label: "OAuth2", Fields: []string{"OVH_ENDPOINT", "OVH_CLIENT_ID", "OVH_CLIENT_SECRET"}, Optional: []string{}},
		{ID: "token", Label: "Access token", Fields: []string{"OVH_ENDPOINT", "OVH_ACCESS_TOKEN"}, Optional: []string{}},
	},
	"route53": {
		{ID: "access-key", Label: "Access key", Fields: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}, Optional: []string{"AWS_REGION", "AWS_ASSUME_ROLE_ARN", "AWS_EXTERNAL_ID", "AWS_HOSTED_ZONE_ID", "AWS_WAIT_FOR_RECORD_SETS_CHANGED"}},
		{ID: "ambient", Label: ambientLabel, Fields: []string{}, Optional: []string{"AWS_REGION", "AWS_ASSUME_ROLE_ARN", "AWS_EXTERNAL_ID", "AWS_HOSTED_ZONE_ID", "AWS_WAIT_FOR_RECORD_SETS_CHANGED"}},
	},
}

// hiddenFields are server-file/host-config inputs with no inline form: they
// are emitted as serverPath (API rejects, UI hides) and need no method.
var hiddenFields = map[string]bool{
	"AWS_PROFILE":           true, // route53: named profile in the server's AWS config
	"AWS_SDK_LOAD_CONFIG":   true, // route53: read the server's AWS CLI config file
	"AKAMAI_EDGERC":         true, // edgedns: path to a server-side .edgerc
	"AKAMAI_EDGERC_SECTION": true, // edgedns: section of that server-side file
}

const ambientLabel = "Server environment credentials"

// inlineFor maps a derived serverPath field to the inline certforge field
// carrying the same material (see extraCredentialFields).
var inlineFor = map[string]string{
	"TRANSIP_PRIVATE_KEY_PATH": "TRANSIP_PRIVATE_KEY",
	"OCI_PRIVKEY_FILE":         "OCI_PRIVKEY",
}

// methodOverrides replaces the derived id/label of a method where the
// humanized form reads badly. Key: "<code>/<derived id>".
var methodOverrides = map[string]struct{ ID, Label string }{
	"cloudflare/api-email-api-key": {"email-api-key", "Email + API key"},
	"cloudflare/dns-api-token":     {"api-token", "API token"},
	"oraclecloud/privkey-tenancy-ocid-user-ocid-pubkey-fingerprint-region-compartment-ocid": {"api-signing-key", "API signing key"},
}

var aliasRe = regexp.MustCompile(`^Alias to ([A-Z0-9_]+)$`)

// acronyms stay upper-case in labels.
var acronyms = map[string]bool{"API": true, "ID": true, "URL": true, "DNS": true, "OTP": true, "TSIG": true, "OCID": true, "IAM": true, "TLD": true, "IP": true, "JWT": true, "PAT": true, "SSH": true, "CA": true, "RAM": true, "PDD": true, "WAPI": true, "DPM": true}

// goEnv evaluates the env.Get calls of a lego provider's NewDNSProvider.
type goEnv struct {
	consts map[string]ast.Expr
	funcs  map[string]*ast.FuncDecl
}

func loadGoEnv(dir string) (*goEnv, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	e := &goEnv{consts: map[string]ast.Expr{}, funcs: map[string]*ast.FuncDecl{}}
	fset := token.NewFileSet()
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							e.consts[n.Name] = vs.Values[i]
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil {
					e.funcs[d.Name.Name] = d
				}
			}
		}
	}
	return e, nil
}

// str evaluates a string expression: literals, const idents, "+" concat and
// altEnvName(X) (swap envNamespace for altEnvNamespace).
func (e *goEnv) str(x ast.Expr) (string, error) {
	switch x := x.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", fmt.Errorf("non-string literal %s", x.Value)
		}
		return strconv.Unquote(x.Value)
	case *ast.ParenExpr:
		return e.str(x.X)
	case *ast.Ident:
		v, ok := e.consts[x.Name]
		if !ok {
			return "", fmt.Errorf("unresolved const %s", x.Name)
		}
		return e.str(v)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", fmt.Errorf("unsupported operator %s", x.Op)
		}
		l, err := e.str(x.X)
		if err != nil {
			return "", err
		}
		r, err := e.str(x.Y)
		if err != nil {
			return "", err
		}
		return l + r, nil
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "altEnvName" && len(x.Args) == 1 {
			arg, err := e.str(x.Args[0])
			if err != nil {
				return "", err
			}
			ns, err := e.str(&ast.Ident{Name: "envNamespace"})
			if err != nil {
				return "", err
			}
			alt, err := e.str(&ast.Ident{Name: "altEnvNamespace"})
			if err != nil {
				return "", err
			}
			return alt + strings.TrimPrefix(arg, ns), nil
		}
	}
	return "", fmt.Errorf("unsupported expression %T", x)
}

// call is one env.Get / env.GetWithFallback invocation: groups of env var
// names, the first of each group being the canonical one.
type call [][]string

func (e *goEnv) calls() ([]call, error) {
	fn := e.funcs["NewDNSProvider"]
	if fn == nil || fn.Body == nil {
		return nil, nil
	}
	var out []call
	var ferr error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || ferr != nil {
			return ferr == nil
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "env" {
			return true
		}
		var c call
		switch sel.Sel.Name {
		case "Get":
			for _, a := range ce.Args {
				s, err := e.str(a)
				if err != nil {
					ferr = fmt.Errorf("env.Get: %w", err)
					return false
				}
				c = append(c, []string{s})
			}
		case "GetWithFallback":
			for _, a := range ce.Args {
				cl, ok := a.(*ast.CompositeLit)
				if !ok {
					ferr = fmt.Errorf("env.GetWithFallback: non-literal group")
					return false
				}
				var g []string
				for _, el := range cl.Elts {
					s, err := e.str(el)
					if err != nil {
						ferr = fmt.Errorf("env.GetWithFallback: %w", err)
						return false
					}
					g = append(g, s)
				}
				c = append(c, g)
			}
		default:
			return true
		}
		if len(c) > 0 {
			out = append(out, c)
		}
		return true
	})
	return out, ferr
}

// deriveAuthMethods returns the provider's auth methods: its override if any,
// else one method per env.Get call in NewDNSProvider. optional is computed
// for derived methods (overrides list their own).
func deriveAuthMethods(pkgDir string, t providerTOML, props map[string]property) ([]authMethod, error) {
	code := t.Code
	if ov, ok := authOverrides[code]; ok {
		return validateOverride(code, ov, props)
	}
	ge, err := loadGoEnv(pkgDir)
	if err != nil {
		return nil, err
	}
	calls, err := ge.calls()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", code, err)
	}
	canon := func(n string) string {
		if a, ok := props[n]; ok && a.AliasOf != "" {
			n = a.AliasOf
		}
		if in, ok := inlineFor[n]; ok {
			n = in
		}
		return n
	}
	ns := namespacePrefix(props)
	var methods []authMethod
	used := map[string]bool{}
	ids := map[string]int{}
	for _, c := range calls {
		var fields []string
		for _, g := range c {
			names := make([]string, len(g))
			for i, n := range g {
				names[i] = canon(n)
			}
			// lego's TOML may document a later fallback spelling as the
			// canonical one (liquidweb: LWAPI_*): prefer the first name the
			// schema knows.
			for i, n := range names {
				if _, ok := props[n]; ok {
					names[0], names[i] = names[i], names[0]
					break
				}
			}
			// A group whose fallbacks include a field this call already
			// requires is satisfied by it: its own first name is optional.
			covered := false
			for _, n := range names[1:] {
				for _, f := range fields {
					if f == n {
						covered = true
					}
				}
			}
			if covered || contains(fields, names[0]) {
				continue
			}
			fields = append(fields, names[0])
		}
		for _, f := range fields {
			p, ok := props[f]
			if !ok {
				return nil, fmt.Errorf("%s: env var %s read by NewDNSProvider is not in the provider's schema; add an authOverrides entry", code, f)
			}
			if p.ServerPath {
				return nil, fmt.Errorf("%s: env var %s is a server path; add an inlineFor or authOverrides entry", code, f)
			}
		}
		if len(fields) == 0 {
			continue
		}
		id, label := methodIDLabel(ns, fields)
		if ov, ok := methodOverrides[code+"/"+id]; ok {
			id, label = ov.ID, ov.Label
		}
		ids[id]++
		if ids[id] > 1 {
			id = fmt.Sprintf("%s-%d", id, ids[id])
		}
		for _, f := range fields {
			used[f] = true
		}
		methods = append(methods, authMethod{ID: id, Label: label, Fields: fields})
	}
	if len(methods) == 0 {
		return nil, nil
	}
	var optional []string
	for k, p := range props {
		if p.Group == "credentials" && !p.ServerPath && p.AliasOf == "" && !used[k] {
			optional = append(optional, k)
		}
	}
	sort.Strings(optional)
	if optional == nil {
		optional = []string{}
	}
	for i := range methods {
		methods[i].Optional = optional
	}
	return methods, nil
}

func validateOverride(code string, ov []authMethod, props map[string]property) ([]authMethod, error) {
	assigned := map[string]bool{}
	for _, m := range ov {
		for _, f := range append(append([]string{}, m.Fields...), m.Optional...) {
			p, ok := props[f]
			if !ok {
				return nil, fmt.Errorf("%s: authOverrides method %s names %s, which is not in the provider's schema", code, m.ID, f)
			}
			if p.ServerPath {
				return nil, fmt.Errorf("%s: authOverrides method %s names serverPath field %s", code, m.ID, f)
			}
			assigned[f] = true
		}
	}
	var missing []string
	for k, p := range props {
		if p.Group == "credentials" && !p.ServerPath && p.AliasOf == "" && !assigned[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s: credentials fields in no authOverrides method (add to fields/optional or hiddenFields): %s", code, strings.Join(missing, ", "))
	}
	return ov, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// namespacePrefix is the provider's env var namespace ("CF_", "AWS_"): the
// longest common "_"-segment prefix of its canonical credentials-group keys,
// or just the first segment when there is a single such key.
func namespacePrefix(props map[string]property) string {
	var keys []string
	for k, p := range props {
		if p.Group == "credentials" && p.AliasOf == "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	common := strings.Split(keys[0], "_")
	common = common[:len(common)-1]
	if len(keys) == 1 {
		if len(common) > 1 {
			common = common[:1]
		}
	}
	for _, k := range keys[1:] {
		segs := strings.Split(k, "_")
		n := 0
		for n < len(common) && n < len(segs)-1 && common[n] == segs[n] {
			n++
		}
		common = common[:n]
	}
	if len(common) == 0 {
		return ""
	}
	return strings.Join(common, "_") + "_"
}

// methodIDLabel derives a kebab-case id and a humanized label from the
// method's fields with the provider namespace stripped.
func methodIDLabel(ns string, fields []string) (string, string) {
	var ids, labels []string
	for _, f := range fields {
		name := strings.TrimPrefix(f, ns)
		if name == "" {
			name = f
		}
		ids = append(ids, strings.ToLower(strings.ReplaceAll(name, "_", "-")))
		labels = append(labels, humanize(name))
	}
	return strings.Join(ids, "-"), strings.Join(labels, " + ")
}

func humanize(name string) string {
	words := strings.Split(name, "_")
	for i, w := range words {
		if acronyms[w] {
			continue
		}
		w = strings.ToLower(w)
		if i == 0 {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		words[i] = w
	}
	return strings.Join(words, " ")
}
