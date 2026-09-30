package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
)

// Deployer installs one grant: pre_deploy hooks, layout files, target
// files, post_deploy hooks. Every write and remove is confined to
// WriteAllow (see confine.go); an empty WriteAllow refuses everything.
type Deployer struct {
	Files      *FileWriter
	Hooks      *HookRunner
	Log        *slog.Logger
	WriteAllow []string
	// Reg is the agent's deploy target registry (NewTargetsRegistry): every
	// grant's target is looked up here and rendered through the registry's
	// FileTarget/Reloader interfaces, never a hardcoded switch on the type
	// string. A target unknown to Reg, or known but not a FileTarget (a
	// server-run type such as vault-kv, which never reaches the agent —
	// R16), fails the grant outright.
	Reg *targets.Registry
	// HTTP builds the outbound targets.HTTPFactory a target's own Files or
	// Reload call may use (targets.Request.HTTP). AllowLoopback is always
	// true here: an agent-side target already runs inside whatever network
	// the agent itself reaches (Deviations R2), unlike a server-side one,
	// which is gated by the org's allowLoopbackUrls setting.
	HTTP targets.HTTPFactory
}

// NewDeployer constructs a Deployer. An empty writeAllow disables every
// write and remove (each grant then fails with a clear per-grant error), so
// this logs a warning once, immediately, rather than only on the first grant.
func NewDeployer(log *slog.Logger, files *FileWriter, hooks *HookRunner, writeAllow []string, reg *targets.Registry, http targets.HTTPFactory) *Deployer {
	if len(writeAllow) == 0 {
		log.Warn("CF_WRITE_ALLOW is empty: certforge-agent will refuse to write or remove any file until it is set")
	}
	return &Deployer{Files: files, Hooks: hooks, Log: log, WriteAllow: writeAllow, Reg: reg, HTTP: http}
}

// resolveFileTarget looks typ up in d.Reg and returns it as a FileTarget:
// an unknown type, or one that is not a FileTarget (a server-run type such
// as vault-kv), is refused with the same message Deploy and
// DeployTargetOnly both surface as the grant's GrantResult.Error.
func (d *Deployer) resolveFileTarget(typ string) (targets.Target, targets.FileTarget, error) {
	t, ok := d.Reg.Get(typ)
	if ok {
		if ft, isFile := t.(targets.FileTarget); isFile {
			return t, ft, nil
		}
	}
	return nil, nil, fmt.Errorf("target type %q is not supported by this agent", typ)
}

// targetRequest builds the targets.Request a's target sees (Files, Paths,
// Reload): GrantID, CertID, CertName, Names and Fingerprint come straight
// off the assignment; Config is a.Target.Config, already the target's
// fully merged config (public fields plus resolved secrets, agents.Service
// render/Assignments); Material is left nil for the caller to set. Side is
// always Agent and HTTP is d.HTTP (Deviations R2).
func (d *Deployer) targetRequest(a agentproto.Assignment) targets.Request {
	return targets.Request{GrantID: a.ID.String(), CertID: a.CertificateID.String(), CertName: a.CertificateName,
		Names: a.CertificateNames, Fingerprint: a.Fingerprint, Config: a.Target.Config, Side: targets.Agent, HTTP: d.HTTP}
}

// redactTargetError runs err through targets.Redact using t's own secret
// property values, split out of cfg (targets.Split) — never logged or
// echoed raw: a target's error could otherwise echo a secret straight back
// (an HTTP call's response body, for example) before it ever reaches
// GrantResult.Error (Global Constraints, Secrets row). A cfg that fails to
// split (should not happen — the server never sends this agent a config it
// has not itself validated) redacts nothing rather than failing again.
func redactTargetError(t targets.Target, cfg json.RawMessage, err error) string {
	_, secrets, splitErr := targets.Split(t.Schema(), cfg)
	if splitErr != nil {
		secrets = nil
	}
	return targets.Redact(err, secrets, targets.MaxDetail)
}

func hookEnv(a agentproto.Assignment, files []delivery.File) []string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	var versionID string
	if a.VersionID != nil {
		versionID = a.VersionID.String()
	}
	return []string{"CF_GRANT_ID=" + a.ID.String(), "CF_CERTIFICATE_NAME=" + a.CertificateName,
		"CF_VERSION_ID=" + versionID, "CF_FINGERPRINT=" + a.Fingerprint, "CF_FILES=" + strings.Join(paths, ":")}
}

// parseMode parses an octal mode and refuses one that is world-writable,
// independently of any check the server already made: a compromised or
// buggy server should not be able to make the agent install a
// world-writable file, in particular a private key.
func parseMode(s string) (os.FileMode, error) {
	m, err := delivery.ParseMode(s)
	if err != nil {
		return 0, err
	}
	if m&0o002 != 0 {
		return 0, fmt.Errorf("mode %s must not be world-writable", s)
	}
	return m, nil
}

// writeFile parses f's mode, confines its path (re-resolved right here, not
// a first pass's cached path: a pre_deploy hook runs arbitrary code and
// could have swapped a symlink into the path since any earlier check), and
// writes it atomically, returning the FileSpec Report/Installed and
// state.json record. Shared by Deploy's per-file loop and DeployTargetOnly.
func (d *Deployer) writeFile(f delivery.File) (agentproto.FileSpec, error) {
	mode, err := parseMode(f.Mode)
	if err != nil {
		return agentproto.FileSpec{}, fmt.Errorf("%s: %w", f.Path, err)
	}
	real, err := confine(d.WriteAllow, f.Path)
	if err != nil {
		return agentproto.FileSpec{}, err
	}
	if err := d.Files.Write(real, f.Data, mode, f.Owner, f.Group); err != nil {
		return agentproto.FileSpec{}, fmt.Errorf("write %s: %w", f.Path, err)
	}
	return agentproto.FileSpec{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, SHA256: delivery.Digest(f.Data)}, nil
}

// Deploy returns the result to report, the files written in write order,
// and (only when the grant has a Traefik target) the certs/<name>
// directory the target created, for Remove to prune once empty.
func (d *Deployer) Deploy(ctx context.Context, a agentproto.Assignment, b agentproto.Bundle) (agentproto.GrantResult, []agentproto.FileSpec, string) {
	res := agentproto.GrantResult{GrantID: a.ID, VersionID: b.VersionID, State: agentproto.StateOK, Installed: []agentproto.FileDigest{}}
	var written []agentproto.FileSpec
	fail := func(format string, args ...any) (agentproto.GrantResult, []agentproto.FileSpec, string) {
		res.State, res.Error = agentproto.StateFailed, fmt.Sprintf(format, args...)
		return res, written, ""
	}
	if a.VersionID == nil {
		return fail("assignment %s has no version; nothing to deploy against a bundle", a.ID)
	}
	if b.VersionID != *a.VersionID {
		return fail("bundle version %s does not match assignment version %s", b.VersionID, *a.VersionID)
	}
	files := make([]delivery.File, 0, len(b.Files)+3)
	for _, f := range b.Files {
		files = append(files, delivery.File{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, Data: f.Content})
	}
	var certsDir string
	var target targets.Target
	var mat *render.Material
	if a.Target != nil {
		t, ft, err := d.resolveFileTarget(a.Target.Type)
		if err != nil {
			return fail("%s", err)
		}
		target = t
		if a.ID == uuid.Nil {
			return fail("target: grant id is required")
		}
		req := d.targetRequest(a)
		if b.Material == nil {
			// a.VersionID is non-nil here (checked above), so this is a
			// genuinely versioned assignment whose bundle nonetheless has no
			// material: never write only the target's material-independent
			// files (Traefik's ACME router file) and call it ok — the
			// server's expected list for a versioned target always includes
			// the certificate files too, so a partial write like that would
			// report ok while the server's own digest comparison marks it
			// drift. A version-less grant (C3) never reaches here at all:
			// Reconcile routes it to DeployTargetOnly instead, which never
			// fetches a bundle in the first place.
			return fail("the bundle has no key material for the %s target", a.Target.Type)
		}
		var merr error
		if mat, merr = targets.MaterialFromPEM(b.Material.Fullchain, b.Material.Key); merr != nil {
			return fail("target: %v", merr)
		}
		req.Material = mat
		tfiles, err := ft.Files(req)
		if err != nil {
			res.State, res.Error = agentproto.StateFailed, redactTargetError(t, a.Target.Config, fmt.Errorf("target: %w", err))
			return res, written, ""
		}
		files = append(files, tfiles...)
		// certsDir (the certs/<name> directory Remove prunes once empty) is
		// a Traefik-specific directory-nesting convention with no generic
		// FileTarget equivalent; every other file target simply has nothing
		// pruned here.
		if a.Target.Type == "traefik" {
			if cfg, err := delivery.ParseTraefik(a.Target.Config); err == nil {
				certsDir = path.Join(cfg.Dir, "certs", delivery.SafeName(a.CertificateName))
			}
		}
	}
	// A first pass fails fast, before any hook runs, on a path that is
	// unclean or outside CF_WRITE_ALLOW right now.
	for _, f := range files {
		if err := delivery.CleanPath("path", f.Path); err != nil {
			return fail("refusing to write %q: %v", f.Path, err)
		}
		if _, err := confine(d.WriteAllow, f.Path); err != nil {
			return fail("%v", err)
		}
	}
	env := hookEnv(a, files)
	for _, h := range a.Hooks {
		if h.Phase != "pre_deploy" {
			continue
		}
		run := d.Hooks.Run(ctx, h, env)
		res.HookRuns = append(res.HookRuns, run)
		if run.ExitCode != 0 {
			return fail("pre_deploy hook %s exited %d; files were not written", h.Argv[0], run.ExitCode)
		}
	}
	for _, f := range files {
		spec, err := d.writeFile(f)
		if err != nil {
			return fail("%v", err)
		}
		written = append(written, spec)
		res.Installed = append(res.Installed, agentproto.FileDigest{Path: spec.Path, SHA256: spec.SHA256})
	}
	// A target whose files need a service reloaded (targets.Reloader) is
	// reloaded once, after every file is written and before post_deploy
	// hooks run: the files are already correct on disk at this point, so a
	// reload failure never undoes them — it only means the running service
	// has not yet picked the new ones up.
	if target != nil {
		if r, ok := target.(targets.Reloader); ok {
			req := d.targetRequest(a)
			req.Material = mat
			if _, err := r.Reload(ctx, req); err != nil {
				res.State, res.Error = agentproto.StateFailed,
					fmt.Sprintf("files installed; reload: %s", redactTargetError(target, a.Target.Config, err))
			}
		}
	}
	for _, h := range a.Hooks {
		if h.Phase != "post_deploy" {
			continue
		}
		run := d.Hooks.Run(ctx, h, env)
		res.HookRuns = append(res.HookRuns, run)
		if run.ExitCode != 0 && res.State == agentproto.StateOK {
			res.State, res.Error = agentproto.StateFailed, fmt.Sprintf("post_deploy hook %s exited %d; the files are installed", h.Argv[0], run.ExitCode)
		}
	}
	return res, written, certsDir
}

// DeployTargetOnly installs a version-less grant's target-only files —
// whatever its registered FileTarget's own Files renders with Material nil
// (today, only Traefik's ACME router file, when acmeServiceUrl is set) —
// straight from a.Target's config, with no bundle fetch and no certificate
// material at all (C3: a grant on a certificate with no version yet,
// reported by Assignments with VersionID nil). Hooks do not run here: they
// are about the certificate's own lifecycle (for example reloading a
// consumer), which has nothing to react to before a first version exists;
// the normal Deploy path runs them, and any Reloader, once one does.
func (d *Deployer) DeployTargetOnly(a agentproto.Assignment) (agentproto.GrantResult, []agentproto.FileSpec, string) {
	res := agentproto.GrantResult{GrantID: a.ID, State: agentproto.StateOK, Installed: []agentproto.FileDigest{}}
	var written []agentproto.FileSpec
	fail := func(format string, args ...any) (agentproto.GrantResult, []agentproto.FileSpec, string) {
		res.State, res.Error = agentproto.StateFailed, fmt.Sprintf(format, args...)
		return res, written, ""
	}
	if a.Target == nil {
		return res, written, ""
	}
	t, ft, err := d.resolveFileTarget(a.Target.Type)
	if err != nil {
		return fail("%s", err)
	}
	if a.ID == uuid.Nil {
		return fail("target: grant id is required")
	}
	req := d.targetRequest(a)
	tfiles, err := ft.Files(req)
	if err != nil {
		res.State, res.Error = agentproto.StateFailed, redactTargetError(t, a.Target.Config, fmt.Errorf("target: %w", err))
		return res, written, ""
	}
	for _, f := range tfiles {
		if err := delivery.CleanPath("path", f.Path); err != nil {
			return fail("refusing to write %q: %v", f.Path, err)
		}
		spec, err := d.writeFile(f)
		if err != nil {
			return fail("%v", err)
		}
		written = append(written, spec)
		res.Installed = append(res.Installed, agentproto.FileDigest{Path: spec.Path, SHA256: spec.SHA256})
	}
	return res, written, ""
}

// Remove deletes files in reverse write order, so a Traefik YAML goes
// before the certificates it references, and prunes certsDir once empty:
// the exact certs/<name> directory Deploy's Traefik target created for
// this grant, or "" when the grant had no target.
func (d *Deployer) Remove(files []agentproto.FileSpec, certsDir string) ([]string, error) {
	removed := make([]string, 0, len(files))
	for i := len(files) - 1; i >= 0; i-- {
		p := files[i].Path
		if err := delivery.CleanPath("path", p); err != nil {
			return removed, err
		}
		real, err := confine(d.WriteAllow, p)
		if err != nil {
			return removed, err
		}
		if err := d.Files.Remove(real); err != nil {
			return removed, err
		}
		removed = append(removed, p)
	}
	if certsDir != "" {
		if err := delivery.CleanPath("path", certsDir); err == nil {
			if real, err := confine(d.WriteAllow, certsDir); err == nil {
				_ = os.Remove(real) // only succeeds once empty
			}
		}
	}
	return removed, nil
}
