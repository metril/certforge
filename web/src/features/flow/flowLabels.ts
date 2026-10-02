import type { FlowNodeData, FlowStatus } from './flowGraph';

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
    if (status === 'idle') return detail === 'Disabled' ? 'Disabled' : 'No deliveries yet';
  }
  return DEFAULT[status];
}
