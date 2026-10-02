import { Card } from '@/components/Card';
import { useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Ban, ChevronDown, CircleAlert, CircleCheck, Clock } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { hookRunsInfinite } from '@/api/queries/clients';
import type { HookRun } from '@/api/types';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { SnippetBlock } from '@/components/SnippetBlock';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { PHASE_LABEL } from '@/lib/clientStatus';
import { help } from '@/lib/help';
import { fmtDateTime, fmtDuration, relTime } from '@/lib/time';
import { cn } from '@/lib/utils';

const COLS = 'md:grid-cols-[96px_minmax(0,140px)_96px_minmax(0,1fr)_80px_72px_28px]';

// The agent (internal/agent/hooks.go) appends this exact marker to stderr
// when it kills the hook at its timeout; exitCode -1 otherwise means it was
// never allowed to run (empty argv, or argv[0] not in CF_HOOK_ALLOW) or
// failed to start.
const TIMED_OUT = /\[certforge-agent: killed after /;

function ExitChip({ code, stderr }: { code: number; stderr: string }) {
  const chip =
    code === 0 ? (
      <ToneChip tone="valid" icon={CircleCheck} label="0" />
    ) : code === -1 ? (
      TIMED_OUT.test(stderr) ? <ToneChip tone="failed" icon={Clock} label="Timed out" /> : <ToneChip tone="failed" icon={Ban} label="Not run" />
    ) : (
      <ToneChip tone="failed" icon={CircleAlert} label={String(code)} />
    );
  // The column header's HelpTip (hook.exit) is hidden below `md` along with
  // the rest of the header row, so the chip carries its own tooltip too —
  // the only place that explanation is reachable at phone width.
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex w-fit">
          {chip}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{help['hook.exit'].text}</TooltipContent>
    </Tooltip>
  );
}

function Output({ run }: { run: HookRun }) {
  if (!run.stdout && !run.stderr) return <p className="text-sm text-ink-muted">No output.</p>;
  return (
    <div className="grid gap-2">
      {run.stdout && <SnippetBlock label="stdout" value={run.stdout} />}
      {run.stderr && <SnippetBlock label="stderr" value={run.stderr} />}
    </div>
  );
}

export function HookRunsTab({ orgId, clientId, onOpenCertificates }: { orgId: string; clientId: string; onOpenCertificates: () => void }) {
  const q = useInfiniteQuery(hookRunsInfinite(orgId, clientId));
  const [open, setOpen] = useState<string | null>(null);
  if (q.isError) return <ErrorState message={`Couldn't load hook runs. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  const runs = q.data.pages.flatMap((p) => p.items);
  if (runs.length === 0) {
    return (
      <EmptyState message="No hook runs yet.">
        <Button variant="outline" onClick={onOpenCertificates}>
          Open certificates
        </Button>
      </EmptyState>
    );
  }
  return (
    <Card className="grid gap-2 p-4">
      {/* Not aria-hidden: it holds the focusable hook.exit tip. */}
      <div className={cn('hidden gap-3 border-b border-border pb-1 text-xs text-ink-muted md:grid', COLS)}>
        <span>Ran</span>
        <span>Hook</span>
        <span>Phase</span>
        <span>Command</span>
        <span className="inline-flex items-center gap-1">
          Exit <HelpTip id="hook.exit" />
        </span>
        <span>Duration</span>
        <span />
      </div>
      <ul aria-label="Hook runs" className="grid">
        {runs.map((r) => {
          const name = r.hookName || 'Deleted hook';
          const command = r.argv.join(' ');
          return (
            <li key={r.id} className="grid gap-2 border-b border-border py-2 text-sm last:border-0">
              <div className={cn('grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 md:min-h-8', COLS)}>
                <time dateTime={r.ranAt} title={fmtDateTime(r.ranAt)} className="text-xs text-ink-muted">
                  {relTime(r.ranAt, q.dataUpdatedAt)}
                </time>
                <span title={name} className={cn('truncate', !r.hookName && 'text-ink-muted')}>
                  {name}
                </span>
                <span className="text-xs">{PHASE_LABEL[r.phase]}</span>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span tabIndex={0} className="col-span-2 truncate font-mono text-xs md:col-span-1">
                      {command}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="max-w-96 break-all font-mono text-xs">
                    {command}
                  </TooltipContent>
                </Tooltip>
                <ExitChip code={r.exitCode} stderr={r.stderr} />
                <span className="text-xs tabular-nums">{fmtDuration(r.durationMs)}</span>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="size-7"
                  aria-expanded={open === r.id}
                  aria-label={`Output of ${name}`}
                  onClick={() => setOpen(open === r.id ? null : r.id)}
                >
                  <ChevronDown className={cn('size-4 transition-transform', open === r.id && 'rotate-180')} aria-hidden />
                </Button>
              </div>
              {open === r.id && <Output run={r} />}
            </li>
          );
        })}
      </ul>
      {q.hasNextPage && (
        <Button variant="outline" className="w-fit" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
          Load more
        </Button>
      )}
    </Card>
  );
}
