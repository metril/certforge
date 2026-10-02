import { Link } from '@tanstack/react-router';
import { Lock } from 'lucide-react';
import type { FlowNodeData, LaneKey } from './flowGraph';
import { FlowNode } from './FlowNode';

export const LANE_META: Record<LaneKey, { title: string; empty: string; cta: string; to: '/o/$org/issuers' | '/o/$org/certificates/new' | '/o/$org/delivery' | '/o/$org/clients/new' | '/o/$org/alerts/channels' }> = {
  issuers: { title: 'Issuers', empty: 'No issuers yet.', cta: 'Add an issuer', to: '/o/$org/issuers' },
  certificates: { title: 'Certificates', empty: 'No certificates yet.', cta: 'Create a certificate', to: '/o/$org/certificates/new' },
  delivery: { title: 'Delivery', empty: 'Nothing delivers certificates yet.', cta: 'Set up delivery', to: '/o/$org/delivery' },
  clients: { title: 'Clients', empty: 'No clients yet.', cta: 'Add a client', to: '/o/$org/clients/new' },
  alerts: { title: 'Alerts', empty: 'No alert channels yet.', cta: 'Add a channel', to: '/o/$org/alerts/channels' },
};

const SUBGROUPS: Partial<Record<LaneKey, { title: string; kinds: FlowNodeData['kind'][] }[]>> = {
  issuers: [
    { title: 'CAs', kinds: ['ca'] },
    { title: 'ACME accounts', kinds: ['account'] },
    { title: 'DNS credentials', kinds: ['dnsCredential'] },
  ],
  delivery: [
    { title: 'Layouts', kinds: ['layout'] },
    { title: 'Targets', kinds: ['target'] },
    { title: 'Hooks', kinds: ['hook'] },
  ],
};

type Props = {
  laneKey: LaneKey;
  org: string;
  hidden: boolean;
  nodes: FlowNodeData[];
  /** Total nodes in the lane before any path filter. */
  total: number;
  selectedId?: string;
  /** Ids on the selected path; undefined when nothing is selected. */
  onPath?: Set<string>;
  onSelect: (id: string) => void;
  register: (id: string, el: HTMLElement | null) => void;
};

export function FlowLane({ laneKey, org, hidden, nodes, total, selectedId, onPath, onSelect, register }: Props) {
  const meta = LANE_META[laneKey];
  const item = (n: FlowNodeData) => (
    <li key={n.id} className="min-w-0">
      <FlowNode node={n} selected={n.id === selectedId} dimmed={!!onPath && !onPath.has(n.id)} onSelect={onSelect} register={register} />
    </li>
  );
  const groups = SUBGROUPS[laneKey];
  return (
    <section aria-label={meta.title} data-flow-lane={laneKey} className="relative z-10 grid min-w-0 content-start gap-2">
      <h2 className="flex items-baseline justify-between gap-2 border-b border-border pb-1 text-sm font-semibold">
        {meta.title}
        {!hidden && (
          <span className="text-xs font-normal text-ink-muted" aria-label={`${nodes.length} of ${total}`}>
            {nodes.length === total ? total : `${nodes.length}/${total}`}
          </span>
        )}
      </h2>
      {hidden ? (
        <p className="flex items-center gap-1.5 rounded-md border border-dashed border-border px-2.5 py-2 text-xs text-ink-muted">
          <Lock className="size-3.5 shrink-0" aria-hidden />
          No access
        </p>
      ) : total === 0 ? (
        <div className="grid gap-1 rounded-md border border-dashed border-border px-2.5 py-2 text-xs text-ink-muted">
          <p>{meta.empty}</p>
          <Link to={meta.to} params={{ org }} className="font-semibold text-primary hover:underline">
            {meta.cta}
          </Link>
        </div>
      ) : groups ? (
        <div className="grid gap-3">
          {groups.map((g) => {
            const ns = nodes.filter((n) => g.kinds.includes(n.kind));
            if (ns.length === 0) return null;
            return (
              <div key={g.title} className="grid gap-1.5">
                <h3 className="text-xs text-ink-muted">{g.title}</h3>
                <ul className="grid gap-2">{ns.map(item)}</ul>
              </div>
            );
          })}
        </div>
      ) : (
        <ul className="grid gap-2">{nodes.map(item)}</ul>
      )}
    </section>
  );
}
