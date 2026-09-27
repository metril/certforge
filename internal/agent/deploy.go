package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

// Deployer installs one grant: pre_deploy hooks, layout files, target
// files, post_deploy hooks. Every write and remove is confined to
// WriteAllow (see confine.go); an empty WriteAllow refuses everything.
type Deployer struct {
	Files      *FileWriter
	Hooks      *HookRunner
	Log        *slog.Logger
	WriteAllow []string
}

// NewDeployer constructs a Deployer. An empty writeAllow disables every
// write and remove (each grant then fails with a clear per-grant error), so
// this logs a warning once, immediately, rather than only on the first grant.
func NewDeployer(log *slog.Logger, files *FileWriter, hooks *HookRunner, writeAllow []string) *Deployer {
	if len(writeAllow) == 0 {
		log.Warn("CF_WRITE_ALLOW is empty: certforge-agent will refuse to write or remove any file until it is set")
	}
	return &Deployer{Files: files, Hooks: hooks, Log: log, WriteAllow: writeAllow}
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
	if a.Target != nil {
		cfg, err := delivery.ParseTarget(a.Target.Type, a.Target.Config)
		if err != nil {
			return fail("target: %v", err)
		}
		if b.Material == nil {
			// C3: a grant on a certificate with no version yet has nothing
			// to render its certificate files from, but the target's ACME
			// router file needs no material at all — write that alone
			// instead of failing, so the very first issuance can validate
			// through Traefik.
			f := delivery.AcmeRouterFile(a.CertificateName, cfg)
			if f == nil {
				return fail("the bundle has no key material for the %s target", a.Target.Type)
			}
			files = append(files, *f)
		} else {
			files = append(files, delivery.RenderTraefik(a.CertificateName, cfg, b.Material.Fullchain, b.Material.Key)...)
			certsDir = path.Join(cfg.Dir, "certs", delivery.SafeName(a.CertificateName))
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
		mode, err := parseMode(f.Mode)
		if err != nil {
			return fail("%s: %v", f.Path, err)
		}
		// Re-resolved right before the write, not the first pass's cached
		// path: a pre_deploy hook runs arbitrary code and could have swapped
		// a symlink into the path in between.
		real, err := confine(d.WriteAllow, f.Path)
		if err != nil {
			return fail("%v", err)
		}
		if err := d.Files.Write(real, f.Data, mode, f.Owner, f.Group); err != nil {
			return fail("write %s: %v", f.Path, err)
		}
		sum := delivery.Digest(f.Data)
		written = append(written, agentproto.FileSpec{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, SHA256: sum})
		res.Installed = append(res.Installed, agentproto.FileDigest{Path: f.Path, SHA256: sum})
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
// today, only the Traefik ACME router file (delivery.AcmeRouterFile) when
// acmeServiceUrl is set — straight from a.Target's config, with no bundle
// fetch and no certificate material at all (C3: a grant on a certificate
// with no version yet, reported by Assignments with VersionID nil). Hooks
// do not run here: they are about the certificate's own lifecycle (for
// example reloading a consumer), which has nothing to react to before a
// first version exists; the normal Deploy path runs them once one does.
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
	cfg, err := delivery.ParseTarget(a.Target.Type, a.Target.Config)
	if err != nil {
		return fail("target: %v", err)
	}
	f := delivery.AcmeRouterFile(a.CertificateName, cfg)
	if f == nil {
		return res, written, ""
	}
	if err := delivery.CleanPath("path", f.Path); err != nil {
		return fail("refusing to write %q: %v", f.Path, err)
	}
	real, err := confine(d.WriteAllow, f.Path)
	if err != nil {
		return fail("%v", err)
	}
	mode, err := parseMode(f.Mode)
	if err != nil {
		return fail("%s: %v", f.Path, err)
	}
	if err := d.Files.Write(real, f.Data, mode, f.Owner, f.Group); err != nil {
		return fail("write %s: %v", f.Path, err)
	}
	sum := delivery.Digest(f.Data)
	written = append(written, agentproto.FileSpec{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, SHA256: sum})
	res.Installed = append(res.Installed, agentproto.FileDigest{Path: f.Path, SHA256: sum})
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
