import { relDays, relTime } from '@/lib/time';
import { laneOf, type FlowNodeData, type FlowStatus } from './flowGraph';

const DEFAULT: Record<FlowStatus, string> = {
  valid: 'Healthy',
  expiring: 'Expiring',
  expired: 'Expired',
  failed: 'Failed',
  drift: 'Drift',
  pending: 'Pending',
  idle: 'Idle',
};

const ISSUER_KINDS: ReadonlyArray<FlowNodeData['kind']> = ['ca', 'account', 'dnsCredential'];

/** Chip label for a node: the generic status word reads wrongly on issuers
 * (idle means unused) and channels (idle means disabled or never delivered),
 * so those kinds get their own wording. statusDetail tells the two idle
 * channel states apart. */
export function flowStatusLabel(kind: FlowNodeData['kind'], status: FlowStatus, detail?: string): string {
  if (ISSUER_KINDS.includes(kind)) {
    if (status === 'valid') return 'In use';
    if (status === 'idle') return 'Unused';
  }
  if (kind === 'channel') {
    if (status === 'valid') return 'Delivering';
    if (status === 'failed') return 'Failing';
    if (status === 'pending') return 'Delivery pending';
    if (status === 'idle') return detail === 'Disabled' ? 'Disabled' : 'No deliveries yet';
  }
  return DEFAULT[status];
}

/** Word for the link between two kinds, by lane pair (order-independent). */
export function edgeRelation(a: FlowNodeData['kind'], b: FlowNodeData['kind']): string {
  const lanes = [laneOf(a), laneOf(b)].sort().join('+');
  switch (lanes) {
    case 'certificates+issuers':
      return 'issues';
    case 'certificates+delivery':
      return 'delivered by';
    case 'clients+delivery':
    case 'certificates+clients':
      return 'grant';
    case 'alerts+certificates':
      return 'alerts';
    default:
      return laneOf(a) === 'alerts' || laneOf(b) === 'alerts' ? 'alerts' : 'link';
  }
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** One quiet line under a node's name; empty when there is nothing to add. */
export function nodeMeta(node: FlowNodeData, links?: { up: number; down: number }, now = Date.now()): string {
  const s = node.summary;
  switch (node.kind) {
    case 'certificate':
      return s?.expiresAt ? relDays(s.expiresAt, now) : (s?.versionSerial ?? '');
    case 'client':
      return s?.lastDeployedAt ? `deployed ${relTime(s.lastDeployedAt, now)}` : '';
    case 'target':
    case 'layout':
    case 'hook':
      return s?.clientIds ? plural(s.clientIds.length, 'host', 'hosts') : '';
    case 'ca':
    case 'account':
    case 'dnsCredential':
      return links ? plural(links.down, 'certificate', 'certificates') : '';
    case 'channel':
      return node.coversCertificates ? 'Covers this org' : '';
  }
}
