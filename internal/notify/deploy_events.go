package notify

import (
	"context"
	"fmt"

	"github.com/metril/certforge/internal/deploy"
)

// DeployEvents implements deploy.Events by wrapping an *Emitter: it lets
// internal/deploy's Dispatcher raise a deploy.failed notification
// immediately after a failed server-run deploy attempt, without
// internal/deploy itself importing this package (Global Constraints: no
// import cycle — internal/deploy defines the Events interface,
// this package implements it and is the one that depends on internal/deploy,
// not the other way around). cmd/certforge/serve.go wires this into
// deploy.Dispatcher.Events.
type DeployEvents struct {
	E *Emitter
}

// DeployFailed implements deploy.Events. It uses the exact same DedupeKey
// as scan.go's own ScanFailedServerDeployments
// ("deploy.failed:<grantID>:<versionID>", Deviations R7), so the immediate
// emit here and the hourly scan's backstop dedupe to one
// notification_events row no matter which one fires first. f.LastError is
// already redacted (Dispatcher.fail's own targets.Redact pass) before it
// ever reaches this Details payload. Always emits with a nil tx: by the
// time Dispatcher.fail calls this, the failed deploy attempt has already
// been recorded (and river's retry decided) outside any transaction of
// its own, so there is no caller transaction to join. f.LastError is
// already redacted for secrets (Dispatcher.fail's own targets.Redact pass)
// but can still carry a raw Vault or target transport URL, so this applies
// the same redactURLs pass scan.go's backstop uses before either can win
// the shared dedupe key.
func (d DeployEvents) DeployFailed(ctx context.Context, f deploy.DeployFailure) error {
	ev := Event{
		Kind:      "deploy.failed",
		OrgID:     &f.OrgID,
		Resource:  Resource{ID: f.GrantID.String(), Name: f.CertName + " → " + f.TargetName},
		Summary:   fmt.Sprintf("Deploy to %s failed", f.TargetName),
		Details:   map[string]any{"target": f.TargetName, "lastError": redactURLs(f.LastError)},
		DedupeKey: fmt.Sprintf("deploy.failed:%s:%s", f.GrantID, f.VersionID),
	}
	_, err := d.E.Emit(ctx, nil, ev)
	return err
}

// compile-time check that DeployEvents satisfies deploy.Events.
var _ deploy.Events = DeployEvents{}
