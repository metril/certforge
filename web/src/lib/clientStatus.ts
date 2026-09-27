import { Ban, CircleAlert, CircleCheck, FileDiff, Hourglass, type LucideIcon } from 'lucide-react';
import type { Client, Deployment, DeploymentState, GrantDelivery, HookPhase } from '@/api/types';
import type { HelpKey } from './help';
import { EXPIRING_DAYS, type Tone } from './status';
import { DAY, fmtDateTime } from './time';

export type Connection = 'online' | 'offline' | 'never' | 'revoked';

/** One answer for "is this agent reachable", shared by every screen. */
export function connection(c: Pick<Client, 'status' | 'online' | 'lastSeen'>): Connection {
  if (c.status === 'revoked') return 'revoked';
  if (c.online) return 'online';
  return c.lastSeen ? 'offline' : 'never';
}

// Dot classes use tokens only; `never` is a hollow ring so it reads apart
// from `offline` without relying on colour.
export const CONNECTION_META: Record<Connection, { label: string; dot: string }> = {
  online: { label: 'Online', dot: 'bg-valid' },
  offline: { label: 'Offline', dot: 'bg-ink-muted' },
  never: { label: 'Never connected', dot: 'border-2 border-pending bg-transparent' },
  revoked: { label: 'Revoked', dot: 'bg-failed' },
};

/** design.md Client detail header: "Connected" (live socket) or "Online (pull)"
 * (seen recently without one), "Offline since", "Never connected". */
export function headerConnectionLabel(c: Pick<Client, 'status' | 'connected' | 'online' | 'lastSeen'>): string {
  const k = connection(c);
  if (k === 'online') return c.connected ? 'Connected' : 'Online (pull)';
  return k === 'offline' ? `Offline since ${fmtDateTime(c.lastSeen!)}` : CONNECTION_META[k].label;
}

// The client's own lifecycle status (Pending/Active/Revoked) — a separate,
// sortable column from ConnectionDot's connection reading (I2: the two used
// to share one "Connection" column sorted by `status`, conflating enrolment
// state with reachability).
export const CLIENT_STATUS_META: Record<Client['status'], { label: string; tone: Tone; icon: LucideIcon }> = {
  pending: { label: 'Pending', tone: 'pending', icon: Hourglass },
  active: { label: 'Active', tone: 'valid', icon: CircleCheck },
  revoked: { label: 'Revoked', tone: 'failed', icon: Ban },
};

export const DEPLOY_META: Record<DeploymentState, { label: string; tone: Tone; icon: LucideIcon; help: HelpKey }> = {
  pending: { label: 'Pending', tone: 'pending', icon: Hourglass, help: 'deploy.pending' },
  ok: { label: 'Deployed', tone: 'valid', icon: CircleCheck, help: 'deploy.ok' },
  failed: { label: 'Failed', tone: 'failed', icon: CircleAlert, help: 'deploy.failed' },
  drift: { label: 'Drift', tone: 'drift', icon: FileDiff, help: 'deploy.drift' },
};

export const DELIVERY_LABEL: Record<GrantDelivery, string> = { push: 'Push', pull: 'Pull' };
export const PHASE_LABEL: Record<HookPhase, string> = { pre_deploy: 'Pre-deploy', post_deploy: 'Post-deploy' };

export function agentCertExpiring(c: Pick<Client, 'status' | 'agentCertNotAfter'>, now = Date.now()): boolean {
  if (c.status !== 'active' || !c.agentCertNotAfter) return false;
  return Date.parse(c.agentCertNotAfter) - now < EXPIRING_DAYS * DAY;
}

export type FileRow = { path: string; expected: string | null; installed: string | null; match: 'ok' | 'changed' | 'missing' | 'unexpected' };

/** Expected files in server order, each compared with the agent's report,
 * then any installed path the server did not expect. */
export function fileRows(d: Pick<Deployment, 'expected' | 'installed'>): FileRow[] {
  const installed = new Map(d.installed.map((f) => [f.path, f.sha256]));
  const rows: FileRow[] = d.expected.map((e) => {
    const got = installed.get(e.path);
    const match = !got ? 'missing' : got === e.sha256 ? 'ok' : 'changed';
    return { path: e.path, expected: e.sha256, installed: got || null, match };
  });
  const known = new Set(d.expected.map((e) => e.path));
  for (const f of d.installed) if (!known.has(f.path)) rows.push({ path: f.path, expected: null, installed: f.sha256 || null, match: 'unexpected' });
  return rows;
}

export function shortHash(h: string | null): string {
  return h ? `${h.slice(0, 12)}…` : '–';
}
