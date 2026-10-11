import { useMemo, useState, type MouseEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from '@tanstack/react-router';
import { RotateCw, X } from 'lucide-react';
import { toast } from 'sonner';
import { grantsQuery, targetGrantsQuery, useRedeployGrant } from '@/api/queries/grants';
import { useRenewCertificates } from '@/api/queries/certificates';
import type { Grant } from '@/api/types';
import { IconButton } from '@/components/IconButton';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { renewToastHandlers } from '@/lib/renewToast';
import { fmtDate, relDays, relTime } from '@/lib/time';
import { LANE_KEYS, edgeKey, laneIndex, laneOf, pairStatus, type Flow, type FlowEdgeData, type FlowNodeData, type FlowPath, type LaneKey } from './flowGraph';
import { edgeRelation } from './flowLabels';
import { FLOW_STATUS, FlowChip, KIND_META } from './FlowNode';

/** Node hrefs are app paths already carrying the org prefix; anything else gets it added. */
export function resolveHref(href: string, slug: string): string {
  if (href.startsWith('/o/')) return href;
  return `/o/${slug}${href.startsWith('/') ? '' : '/'}${href}`;
}

function useOpenHref(node: FlowNodeData, slug: string) {
  const router = useRouter();
  const href = resolveHref(node.href, slug);
  const go = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    router.history.push(href);
  };
  return { href, go };
}

function OpenLink({ node, slug }: { node: FlowNodeData; slug: string }) {
  const { href, go } = useOpenHref(node, slug);
  return (
    <a href={href} onClick={go} aria-label={`Open ${node.name}`} className="text-xs font-semibold text-primary hover:underline">
      Open
    </a>
  );
}

function OpenButton({ node, slug }: { node: FlowNodeData; slug: string }) {
  const { href, go } = useOpenHref(node, slug);
  return (
    <Button asChild variant="outline" size="sm">
      <a href={href} onClick={go} aria-label={`Open ${node.name}`}>
        Open
      </a>
    </Button>
  );
}

const STEP_TITLE: Record<LaneKey, string> = { issuers: 'Issuer', certificates: 'Certificate', delivery: 'Delivery', clients: 'Client', alerts: 'Alert' };
const STEP_CAP = 8;
const rawIdOf = (id: string): string => id.slice(id.indexOf(':') + 1);

type Props = {
  flow: Flow;
  nodes: FlowNodeData[];
  path: FlowPath;
  node?: FlowNodeData;
  edge?: { from: string; to: string };
  slug: string;
  orgId: string;
  wide: boolean;
  onClose: () => void;
  onSelectNode: (id: string) => void;
  onSelectEdge: (from: string, to: string) => void;
};

function Summary({ node }: { node: FlowNodeData }) {
  const s = node.summary;
  if (!s) return null;
  const rows: { label: string; value: React.ReactNode; wide?: boolean }[] = [];
  if (s.expiresAt)
    rows.push({
      label: 'Expires',
      value: (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0}>{relDays(s.expiresAt)}</span>
          </TooltipTrigger>
          <TooltipContent>{fmtDate(s.expiresAt)}</TooltipContent>
        </Tooltip>
      ),
    });
  if (s.versionSerial) rows.push({ label: 'Version', value: <span className="font-mono text-xs break-all">{s.versionSerial}</span> });
  if (s.lastDeployedAt) rows.push({ label: 'Last deployed', value: relTime(s.lastDeployedAt) });
  if (s.counts) {
    rows.push({ label: 'Grants', value: s.counts.grants });
    rows.push({ label: 'Deployments', value: s.counts.deployments });
    rows.push({ label: 'Problems', value: <span className={s.counts.problems > 0 ? 'text-failed' : undefined}>{s.counts.problems}</span> });
  }
  if (s.lastError) rows.push({ label: 'Last error', value: <span className="text-xs text-failed break-words">{s.lastError}</span>, wide: true });
  if (rows.length === 0) return null;
  return (
    <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-sm">
      {rows.map((r) => (
        <div key={r.label} className={r.wide ? 'col-span-2' : undefined}>
          <dt className="text-xs text-ink-muted">{r.label}</dt>
          <dd>{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Stepper({ node, nodes, path, slug, onSelectNode }: { node: FlowNodeData; nodes: FlowNodeData[]; path: FlowPath; slug: string; onSelectNode: (id: string) => void }) {
  const onPath = useMemo(() => nodes.filter((n) => path.nodes.has(n.id)), [nodes, path]);
  return (
    <ol aria-label="Path" className="grid gap-3">
      {LANE_KEYS.map((k) => {
        const ns = onPath.filter((n) => laneOf(n.kind) === k);
        const label = `${STEP_TITLE[k]}, ${ns.length} ${ns.length === 1 ? 'item' : 'items'}`;
        return (
          <li key={k} aria-label={label} className="grid gap-1">
            <div className="flex items-center gap-2">
              <span aria-hidden className={ns.length > 0 ? 'size-2 shrink-0 rounded-full bg-primary' : 'size-2 shrink-0 rounded-full border border-border'} />
              <span className="text-xs uppercase tracking-wide text-ink-muted">{STEP_TITLE[k]}</span>
            </div>
            <div className="ml-1 grid gap-1 border-l border-border pl-4">
              {ns.length === 0 && <span className="text-xs text-ink-muted">None</span>}
              {ns.slice(0, STEP_CAP).map((n) => (
                <div key={n.id} className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                  {n.id === node.id ? (
                    <span aria-current="true" className="min-w-0 truncate font-semibold">
                      {n.name}
                    </span>
                  ) : (
                    <button type="button" onClick={() => onSelectNode(n.id)} className="min-w-0 truncate rounded-sm text-left hover:underline focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none">
                      {n.name}
                    </button>
                  )}
                  {n.status !== 'valid' && <FlowChip node={n} />}
                  {n.id !== node.id && <OpenLink node={n} slug={slug} />}
                </div>
              ))}
              {ns.length > STEP_CAP && <span className="text-xs text-ink-muted">and {ns.length - STEP_CAP} more</span>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/** Pair ordered by lane, so a link always reads left to right like the map. */
const ordered = (a: FlowNodeData, b: FlowNodeData): [FlowNodeData, FlowNodeData] => (laneIndex(a.kind) <= laneIndex(b.kind) ? [a, b] : [b, a]);

function Links({ flow, node, byId, onSelectEdge }: { flow: Flow; node: FlowNodeData; byId: Map<string, FlowNodeData>; onSelectEdge: (from: string, to: string) => void }) {
  const items = useMemo(() => {
    const pairs = new Map<string, FlowEdgeData[]>();
    for (const e of flow.edges) {
      if (e.from !== node.id && e.to !== node.id) continue;
      const k = edgeKey(e.from, e.to);
      pairs.set(k, [...(pairs.get(k) ?? []), e]);
    }
    return [...pairs.values()].flatMap((es) => {
      const e = es[0]!;
      const other = byId.get(e.from === node.id ? e.to : e.from);
      return other ? [{ key: edgeKey(e.from, e.to), other, status: pairStatus(es), pair: ordered(node, other) }] : [];
    });
  }, [flow, node, byId]);
  if (items.length === 0) return null;
  return (
    <div className="grid gap-1">
      <h3 className="text-xs uppercase tracking-wide text-ink-muted">Links</h3>
      <ul className="grid gap-0.5">
        {items.map((it) => (
          <li key={it.key}>
            <button type="button" onClick={() => onSelectEdge(it.pair[0].id, it.pair[1].id)} className="max-w-full truncate rounded-sm text-left text-sm hover:underline focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none">
              → {it.other.name} · {FLOW_STATUS[it.status].label.toLowerCase()}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function RenewButton({ node, orgId }: { node: FlowNodeData; orgId: string }) {
  const me = useMe();
  const renew = useRenewCertificates(orgId);
  const allowed = can(me, 'certs:issue', orgId);
  return (
    <PermissionTip allowed={allowed} action="certs:issue">
      <Button size="sm" disabled={!allowed || renew.isPending} onClick={() => renew.mutate([rawIdOf(node.id)], renewToastHandlers(node.name))}>
        <RotateCw className="size-4" aria-hidden />
        Renew
      </Button>
    </PermissionTip>
  );
}

function RedeployButton({ node, orgId, path }: { node: FlowNodeData; orgId: string; path: FlowPath }) {
  const me = useMe();
  const allowed = can(me, 'clients:write', orgId);
  const rid = rawIdOf(node.id);
  const q = useQuery({ ...((node.kind === 'target' ? targetGrantsQuery(orgId, rid) : grantsQuery(orgId, rid)) as ReturnType<typeof grantsQuery>), enabled: allowed });
  const redeploy = useRedeployGrant(orgId, true);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const certs = useMemo(() => new Set([...path.nodes].filter((id) => id.startsWith('certificate:')).map(rawIdOf)), [path]);
  const scoped = certs.size > 0;
  const grants: Grant[] = useMemo(() => (q.data ?? []).filter((g) => !scoped || certs.has(g.certificateId)), [q.data, scoped, certs]);
  const n = grants.length;
  const run = async () => {
    setConfirm(false);
    setBusy(true);
    let ok = 0;
    for (const g of grants) {
      try {
        await redeploy.mutateAsync(g.id);
        ok++;
      } catch {
        // counted below
      }
    }
    setBusy(false);
    if (ok === n) toast.success(`Redeployed ${ok}`);
    else toast.error(`Redeployed ${ok} of ${n}; ${n - ok} failed.`);
  };
  const none = allowed && !q.isPending && n === 0;
  return (
    <>
      <PermissionTip allowed={allowed && !none} action="clients:write" reason={none ? 'No grants to redeploy' : undefined}>
        <Button variant="outline" size="sm" disabled={!allowed || n === 0 || busy} onClick={() => setConfirm(true)}>
          <RotateCw className="size-4" aria-hidden />
          Redeploy
        </Button>
      </PermissionTip>
      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Redeploy grants?</DialogTitle>
            <DialogDescription>
              Redeploy {n} {n === 1 ? 'grant' : 'grants'} of {node.name}
              {scoped ? ' on this path' : ''}.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button onClick={() => void run()}>Redeploy</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function Name({ node, onSelectNode }: { node: FlowNodeData; onSelectNode: (id: string) => void }) {
  return (
    <button type="button" onClick={() => onSelectNode(node.id)} className="min-w-0 truncate rounded-sm font-semibold hover:underline focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none">
      {node.name}
    </button>
  );
}

function EdgeBody({ flow, byId, edge, slug, onSelectNode }: { flow: Flow; byId: Map<string, FlowNodeData>; edge: { from: string; to: string }; slug: string; onSelectNode: (id: string) => void }) {
  const from = byId.get(edge.from);
  const to = byId.get(edge.to);
  const es = flow.edges.filter((e) => edgeKey(e.from, e.to) === edgeKey(edge.from, edge.to));
  const carried = useMemo(() => {
    const ids = new Set<string>();
    for (const n of [from, to]) if (n?.kind === 'certificate') ids.add(n.id);
    if (ids.size === 0) for (const e of es) if (e.certificateId) ids.add(`certificate:${e.certificateId}`);
    return [...ids].flatMap((id) => (byId.has(id) ? [byId.get(id)!] : []));
  }, [from, to, es, byId]);
  if (!from || !to) return null;
  const status = es.length > 0 ? pairStatus(es) : 'idle';
  const m = FLOW_STATUS[status];
  return (
    <>
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <Name node={from} onSelectNode={onSelectNode} />
        <span aria-hidden className="text-ink-muted">→</span>
        <Name node={to} onSelectNode={onSelectNode} />
      </div>
      <div className="flex items-center gap-2 text-sm">
        <ToneChip tone={m.tone} icon={m.icon} label={m.label} />
        <span className="text-ink-muted">{edgeRelation(from.kind, to.kind)}</span>
      </div>
      {carried.length > 0 && (
        <div className="grid gap-1">
          <h3 className="text-xs uppercase tracking-wide text-ink-muted">Certificates carried</h3>
          <ul className="grid gap-1">
            {carried.map((c) => (
              <li key={c.id} className="flex min-w-0 items-center gap-2 text-sm">
                <span className="min-w-0 truncate">{c.name}</span>
                <OpenLink node={c} slug={slug} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

/** Detail of the selected node (path stepper, summary, actions) or connection. Inline sticky aside on wide screens, bottom sheet on narrow ones. */
export function FlowDetailSheet({ flow, nodes, path, node, edge, slug, orgId, wide, onClose, onSelectNode, onSelectEdge }: Props) {
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const Icon = node ? KIND_META[node.kind].icon : null;
  const title = node ? node.name : 'Link';
  const body = (
    <>
      <div className="flex min-w-0 items-center gap-2 pr-6">
        {Icon && <Icon className="size-4 shrink-0 text-ink-muted" aria-hidden />}
        {wide ? <h2 className="min-w-0 truncate text-base font-semibold">{title}</h2> : <SheetTitle className="min-w-0 truncate text-base">{title}</SheetTitle>}
        {node && <FlowChip node={node} />}
        {wide && <IconButton label="Close" variant="ghost" size="icon-xs" className="ml-auto" onClick={onClose}><X className="size-4" aria-hidden /></IconButton>}
      </div>
      {!wide && <SheetDescription className="sr-only">{node ? `${KIND_META[node.kind].label} details and path` : 'Connection details'}</SheetDescription>}
      {node ? (
        <>
          <Summary node={node} />
          <Stepper node={node} nodes={nodes} path={path} slug={slug} onSelectNode={onSelectNode} />
          <Links flow={flow} node={node} byId={byId} onSelectEdge={onSelectEdge} />
          <div className="flex flex-wrap gap-2">
            <OpenButton node={node} slug={slug} />
            {node.kind === 'certificate' && <RenewButton node={node} orgId={orgId} />}
            {(node.kind === 'client' || node.kind === 'target') && <RedeployButton node={node} orgId={orgId} path={path} />}
          </div>
        </>
      ) : edge ? (
        <>
          <EdgeBody flow={flow} byId={byId} edge={edge} slug={slug} onSelectNode={onSelectNode} />
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={onClose}>
              Clear
            </Button>
          </div>
        </>
      ) : null}
    </>
  );
  if (wide)
    return (
      <aside aria-label="Details" className="sticky top-4 grid max-h-dvh w-80 shrink-0 content-start gap-4 overflow-y-auto rounded-md border border-border bg-panel p-4">
        {body}
      </aside>
    );
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="bottom" className="max-h-dvh gap-4 overflow-y-auto p-4">
        {body}
      </SheetContent>
    </Sheet>
  );
}
