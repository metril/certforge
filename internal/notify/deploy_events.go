package notify

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agents"
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

// DeployDrift implements deploy.Events: the server-run grant's deploy.drift
// warning, sent after OnCheck's transaction commits. Same DedupeKey shape as
// the agent-run alert and scan.go, so a repeat for one version never sends twice.
func (d DeployEvents) DeployDrift(ctx context.Context, f deploy.DeployDrift) error {
	_, err := d.E.Emit(ctx, nil, deployStateEvent(f.OrgID, f.GrantID, f.VersionID, "drift", f.CertName, f.TargetName, ""))
	return err
}

// DeploymentChanged implements agents.DeploymentEvents: the agent-run
// deploy.drift/deploy.failed alert, sent right after the report or heartbeat
// commits. It shares scan.go's builder and so its DedupeKey, which makes the
// hourly scan a backstop that cannot send a second copy.
func (d DeployEvents) DeploymentChanged(ctx context.Context, t agents.DeploymentTransition) error {
	_, err := d.E.Emit(ctx, nil, deployStateEvent(t.OrgID, t.GrantID, t.VersionID, t.State, t.CertName, t.Target, t.Error))
	return err
}

var _ agents.DeploymentEvents = DeployEvents{}

// compile-time check that DeployEvents satisfies deploy.Events.
var _ deploy.Events = DeployEvents{}

// DeployNotifier implements deploy.Notifier by sending straight to a channel.
type DeployNotifier struct {
	S *Service
}

// SendDeploy implements deploy.Notifier.
func (d DeployNotifier) SendDeploy(ctx context.Context, orgID, channelID uuid.UUID, n deploy.DeployNotice) error {
	return d.S.SendDirect(ctx, orgID, channelID, Event{
		Kind:     "deploy.notice",
		Severity: "info",
		Resource: Resource{Type: "grant", ID: n.GrantID.String(), Name: n.CertName + " → " + n.TargetName},
		Summary:  fmt.Sprintf("Certificate %s deployed to %s (%s)", n.CertName, n.TargetName, n.Fingerprint),
		Details:  map[string]any{"target": n.TargetName, "certificate": n.CertName, "fingerprint": n.Fingerprint},
	})
}

var _ deploy.Notifier = DeployNotifier{}
