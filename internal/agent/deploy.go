package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

// Deployer installs one grant: pre_deploy hooks, layout files, target
// files, post_deploy hooks.
type Deployer struct {
	Files *FileWriter
	Hooks *HookRunner
	Log   *slog.Logger
}

func hookEnv(a agentproto.Assignment, files []delivery.File) []string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	return []string{"CF_GRANT_ID=" + a.ID.String(), "CF_CERTIFICATE_NAME=" + a.CertificateName,
		"CF_VERSION_ID=" + a.VersionID.String(), "CF_FINGERPRINT=" + a.Fingerprint, "CF_FILES=" + strings.Join(paths, ":")}
}

// Deploy returns the result to report and the files written, in write order.
func (d *Deployer) Deploy(ctx context.Context, a agentproto.Assignment, b agentproto.Bundle) (agentproto.GrantResult, []agentproto.FileSpec) {
	res := agentproto.GrantResult{GrantID: a.ID, VersionID: b.VersionID, State: agentproto.StateOK, Installed: []agentproto.FileDigest{}}
	var written []agentproto.FileSpec
	fail := func(format string, args ...any) (agentproto.GrantResult, []agentproto.FileSpec) {
		res.State, res.Error = agentproto.StateFailed, fmt.Sprintf(format, args...)
		return res, written
	}
	files := make([]delivery.File, 0, len(b.Files)+3)
	for _, f := range b.Files {
		files = append(files, delivery.File{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, Data: f.Content})
	}
	if a.Target != nil {
		cfg, err := delivery.ParseTarget(a.Target.Type, a.Target.Config)
		if err != nil {
			return fail("target: %v", err)
		}
		if b.Material == nil {
			return fail("the bundle has no key material for the %s target", a.Target.Type)
		}
		files = append(files, delivery.RenderTraefik(a.CertificateName, cfg, b.Material.Fullchain, b.Material.Key)...)
	}
	for _, f := range files {
		if err := delivery.CleanPath("path", f.Path); err != nil {
			return fail("refusing to write %q: %v", f.Path, err)
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
		mode, err := delivery.ParseMode(f.Mode)
		if err != nil {
			return fail("%s: %v", f.Path, err)
		}
		if err := d.Files.Write(f.Path, f.Data, mode, f.Owner, f.Group); err != nil {
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
	return res, written
}

// Remove deletes files in reverse write order, so a Traefik YAML goes
// before the certificates it references, and prunes empty certs/<name>/.
func (d *Deployer) Remove(files []agentproto.FileSpec) ([]string, error) {
	removed := make([]string, 0, len(files))
	for i := len(files) - 1; i >= 0; i-- {
		p := files[i].Path
		if err := d.Files.Remove(p); err != nil {
			return removed, err
		}
		removed = append(removed, p)
		if dir := filepath.Dir(p); filepath.Base(filepath.Dir(dir)) == "certs" {
			_ = os.Remove(dir) // only succeeds once empty
		}
	}
	return removed, nil
}
