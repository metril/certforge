import { useMemo, useState } from 'react';
import { ChevronRight, Circle, CircleAlert, CircleCheck, CircleMinus, CircleX, Copy, Loader2, type LucideIcon } from 'lucide-react';
import type { Attempt, AttemptStep } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Input } from '@/components/ui/input';
import { explainAcmeError } from '@/lib/acmeErrors';
import { docsHref } from '@/lib/help';
import type { Tone } from '@/lib/status';
import { fmtDateTime, fmtDuration } from '@/lib/time';
import { cn } from '@/lib/utils';
import { HelpTip } from './HelpTip';
import { ToneChip } from './StatusChip';

const OUTCOME: Record<Attempt['outcome'], { tone: Tone; icon: LucideIcon; label: string }> = {
  running: { tone: 'pending', icon: Loader2, label: 'Running' },
  success: { tone: 'valid', icon: CircleCheck, label: 'Succeeded' },
  failed: { tone: 'failed', icon: CircleAlert, label: 'Failed' },
};

const STEP: Record<string, { icon: LucideIcon; cls: string; label: string }> = {
  success: { icon: CircleCheck, cls: 'text-valid', label: 'Done' },
  failed: { icon: CircleX, cls: 'text-failed', label: 'Failed' },
  running: { icon: Loader2, cls: 'animate-spin text-pending', label: 'Running' },
  skipped: { icon: CircleMinus, cls: 'text-ink-muted', label: 'Skipped' },
  pending: { icon: Circle, cls: 'text-ink-muted', label: 'Waiting' },
  waiting_manual: { icon: Circle, cls: 'text-expiring', label: 'Waiting on you' },
};

function StepRow({ step, expanded }: { step: AttemptStep; expanded: boolean }) {
  const [open, setOpen] = useState(expanded);
  const m = STEP[step.status] ?? STEP.pending!;
  const Icon = m.icon;
  const dur = step.finishedAt ? fmtDuration(Date.parse(step.finishedAt) - Date.parse(step.startedAt)) : null;
  return (
    <li className="grid gap-1">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Icon className={cn('size-4', m.cls)} aria-hidden />
        <span className="sr-only">{m.label}:</span>
        <span className={step.status === 'failed' ? 'font-semibold' : undefined}>{step.name}</span>
        {dur && <span className="text-xs text-ink-muted">{dur}</span>}
        {step.message && !expanded && (
          <Button variant="link" size="sm" className="h-auto px-0" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            {open ? 'Hide details' : 'Details'}
          </Button>
        )}
      </div>
      {step.message && open && <p className="ml-6 whitespace-pre-wrap font-mono text-xs text-ink-muted">{step.message}</p>}
    </li>
  );
}

export function AttemptLogViewer({ attempt, defaultOpen = false }: { attempt: Attempt; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const [logOpen, setLogOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const o = OUTCOME[attempt.outcome];
  const start = Date.parse(attempt.startedAt);
  const duration = (attempt.finishedAt ? Date.parse(attempt.finishedAt) : Date.now()) - start;
  const err = attempt.outcome === 'failed' ? explainAcmeError(attempt.acmeErrorType) : null;
  const failing = attempt.steps.findIndex((s) => s.status === 'failed');
  const lines = useMemo(() => attempt.log.split('\n').map((text, n) => ({ text, n })), [attempt.log]);
  const shown = filter ? lines.filter((l) => l.text.toLowerCase().includes(filter.toLowerCase())) : lines;

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="border-b border-border">
      <CollapsibleTrigger className="flex w-full flex-wrap items-center gap-3 py-2 text-left text-sm hover:bg-subtle">
        <ChevronRight className={cn('size-4 transition-transform', open && 'rotate-90')} aria-hidden />
        <ToneChip tone={o.tone} icon={o.icon} label={o.label} />
        <span>{fmtDateTime(attempt.startedAt)}</span>
        <span className="text-ink-muted">{attempt.finishedAt ? fmtDuration(duration) : `running for ${fmtDuration(duration)}`}</span>
        {attempt.acmeErrorType && <code className="font-mono text-xs">{attempt.acmeErrorType.replace('urn:ietf:params:acme:error:', '')}</code>}
      </CollapsibleTrigger>
      <CollapsibleContent className="grid gap-4 pb-4 pl-7">
        {err && (
          <p className="flex flex-wrap items-center gap-1.5 text-sm">
            <CircleAlert className="size-4 text-failed" aria-hidden />
            {err.text}
            <a href={docsHref(err.href)} target="_blank" rel="noreferrer" className="text-primary underline underline-offset-2">
              {err.fix}
            </a>
          </p>
        )}
        {attempt.retryAfter && attempt.outcome === 'failed' && (
          <p className="flex items-center gap-1.5 text-sm">
            Next retry {fmtDateTime(attempt.retryAfter)}
            <HelpTip id="attempt.retry" />
          </p>
        )}
        <ol aria-label="Steps" className="grid gap-1">
          {attempt.steps.map((s, i) => (
            <StepRow key={`${s.name}-${i}`} step={s} expanded={i === failing} />
          ))}
        </ol>
        <Collapsible open={logOpen} onOpenChange={setLogOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" size="sm" className="w-fit">
              <ChevronRight className={cn('size-4 transition-transform', logOpen && 'rotate-90')} aria-hidden />
              Raw log
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="grid gap-2 pt-2">
            <div className="flex items-center gap-2">
              <Input aria-label="Search log" className="h-8 w-64 font-mono text-xs" placeholder="nxdomain" value={filter} onChange={(e) => setFilter(e.target.value)} />
              <Button variant="outline" size="sm" onClick={() => void navigator.clipboard.writeText(attempt.log)}>
                <Copy className="size-4" aria-hidden />
                Copy log
              </Button>
            </div>
            <pre className="max-h-96 overflow-auto rounded-md border border-border bg-subtle p-3 font-mono text-xs leading-relaxed">
              {shown.map((l) => (
                <div key={l.n} className="flex gap-3">
                  <span className="w-8 shrink-0 select-none text-right text-ink-muted">{l.n + 1}</span>
                  <span className="whitespace-pre-wrap break-all">{l.text}</span>
                </div>
              ))}
            </pre>
          </CollapsibleContent>
        </Collapsible>
      </CollapsibleContent>
    </Collapsible>
  );
}
