import { useQuery } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, CircleAlert, X } from 'lucide-react';
import { actionGroupsQuery, actionsQuery } from '@/api/queries/delivery';
import type { Action as StepAction, ActionGroup as StepGroup, GrantStep } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { HelpTip } from '@/components/HelpTip';
import { IconButton } from '@/components/IconButton';
import { ToneChip } from '@/components/StatusChip';
import { plural } from '@/api/queries/certificates';

export const KIND_LABEL: Record<StepAction['kind'], string> = {
  exec: 'Command',
  restart: 'Restart',
  ssh: 'SSH',
  pfsense_shell: 'pfSense shell',
  pfsense_restart: 'pfSense restart',
  truenas_restart: 'TrueNAS restart',
  routeros_restart: 'RouterOS restart',
  http: 'HTTP',
  notify: 'Notify',
  verify_tls: 'Verify TLS',
  wait: 'Wait',
};

const PHASE: Record<StepAction['phase'], string> = { pre_deploy: 'Pre', post_deploy: 'Post' };

const stepKey = (s: GrantStep) => ('action' in s ? `a:${s.action}` : `g:${s.group}`);

type Props = {
  orgId: string;
  runsOn: 'agent' | 'server';
  value: GrantStep[];
  onChange: (v: GrantStep[]) => void;
  /** Where "New action" goes (the Actions page); opens in a new tab so the form keeps its state. */
  newActionHref?: string;
};

/** An ordered list of grant steps (library actions and groups) with a library picker. */
export function StepsPicker({ orgId, runsOn, value, onChange, newActionHref }: Props) {
  const actionsQ = useQuery(actionsQuery(orgId));
  const groupsQ = useQuery(actionGroupsQuery(orgId));
  const actions = actionsQ.data ?? [];
  const groups = groupsQ.data ?? [];
  const fits = (a: StepAction) => a.runsOn === runsOn;
  const used = new Set(value.map(stepKey));
  const options = [
    ...actions.filter(fits).filter((a) => !used.has(`a:${a.id}`)).map((a) => ({ value: `a:${a.id}`, label: a.name, hint: `${KIND_LABEL[a.kind]} · ${PHASE[a.phase]}` })),
    ...groups.filter((g) => !used.has(`g:${g.id}`)).map((g) => ({ value: `g:${g.id}`, label: g.name, hint: `Group · ${plural(g.actionIds.length, 'action')}` })),
  ];
  const move = (i: number, d: -1 | 1) => {
    const next = [...value];
    [next[i], next[i + d]] = [next[i + d]!, next[i]!];
    onChange(next);
  };
  const add = (v: string | undefined) => {
    if (!v) return;
    onChange([...value, v.startsWith('a:') ? { action: v.slice(2) } : { group: v.slice(2) }]);
  };
  const row = (s: GrantStep): { name: string; kind?: string; badge: string; missing: boolean } => {
    if ('action' in s) {
      const a = actions.find((x) => x.id === s.action);
      return a ? { name: a.name, kind: KIND_LABEL[a.kind], badge: PHASE[a.phase], missing: false } : { name: s.action, badge: 'Missing', missing: true };
    }
    const g: StepGroup | undefined = groups.find((x) => x.id === s.group);
    return g ? { name: g.name, badge: `Group · ${plural(g.actionIds.length, 'action')}`, missing: false } : { name: s.group, badge: 'Missing', missing: true };
  };
  return (
    <div className="grid gap-2">
      <span className="inline-flex items-center gap-1.5 text-sm font-semibold">
        Steps
        <HelpTip id="grant.steps" />
      </span>
      {value.length > 0 && (
        <ol aria-label="Step run order" className="grid gap-1">
          {value.map((s, i) => {
            const r = row(s);
            return (
              <li key={stepKey(s)} className="flex min-h-9 items-center gap-2 rounded-md border border-border px-2 text-sm">
                <span className="w-5 text-right tabular-nums text-ink-muted">{i + 1}.</span>
                <span className="min-w-0 flex-1 truncate">{r.name}</span>
                {r.kind && <span className="text-xs text-ink-muted">{r.kind}</span>}
                {r.missing ? <ToneChip tone="failed" icon={CircleAlert} label={r.badge} /> : <span className="rounded-md bg-subtle px-1.5 py-0.5 text-xs">{r.badge}</span>}
                <IconButton variant="ghost" size="icon-sm" className="size-7" label={`Move ${r.name} up`} disabled={i === 0} onClick={() => move(i, -1)}>
                  <ArrowUp className="size-3.5" aria-hidden />
                </IconButton>
                <IconButton variant="ghost" size="icon-sm" className="size-7" label={`Move ${r.name} down`} disabled={i === value.length - 1} onClick={() => move(i, 1)}>
                  <ArrowDown className="size-3.5" aria-hidden />
                </IconButton>
                <IconButton variant="ghost" size="icon-sm" className="size-7" label={`Remove ${r.name}`} onClick={() => onChange(value.filter((_, j) => j !== i))}>
                  <X className="size-3.5" aria-hidden />
                </IconButton>
              </li>
            );
          })}
        </ol>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-48 flex-1">
          <Combobox
            id="steps-add"
            aria-label="Add from library"
            value={undefined}
            onChange={add}
            options={options}
            placeholder="Add from library"
            emptyText="Nothing left in the library."
          />
        </div>
        {newActionHref && (
          <a href={newActionHref} target="_blank" rel="noreferrer" className="text-sm text-primary hover:underline">
            New action
          </a>
        )}
      </div>
    </div>
  );
}
