// Package deploy is the server-side counterpart to internal/delivery: deploy
// target types whose grants run on this server rather than an enrolled
// agent (client-less "server grants", Deviations R9/R6), and the
// Dispatcher that renders and delivers their certificate material. The
// target types themselves (VaultKV) implement internal/targets.Target and
// register into the shared *targets.Registry (internal/targets), rather
// than a registry of their own — see git history before this task for the
// deploy.Target/Registry/RunsOn/AddToMeta shapes this package used to hold.
// Deviations R6: there is no Probe in 5A — Target has no probe method, and
// nothing calls one.
package deploy
