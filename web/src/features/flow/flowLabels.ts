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
