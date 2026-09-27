import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Check, ChevronRight, Circle, CircleAlert, CircleCheck, CircleMinus, CircleX, Copy, Loader2, TriangleAlert, type LucideIcon } from 'lucide-react';
import type { Attempt, AttemptStep } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Input } from '@/components/ui/input';
import { explainAcmeError } from '@/lib/acmeErrors';
import { docsHref, type HelpKey } from '@/lib/help';
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

// The server's real step names (`caa`, `rate_ledger` since 4A) get readable
// labels; every other step name passes through as-is.
export const STEP_LABEL: Record<string, string> = {
  caa: 'CAA check',
  rate_ledger: 'Rate limits',
};

const STEP_HELP: Partial<Record<string, HelpKey>> = {
  caa: 'attempt.caa',
  rate_ledger: 'attempt.rateLedger',
};

function StepRow({ step, expanded, extra }: { step: AttemptStep; expanded: boolean; extra?: ReactNode }) {
  // Fix round 1 (review, Important): `useState(expanded)` only reads `expanded`
  // on first mount, so a step that turns from running to failed on a later
  // poll (same StepRow instance — same key) kept its message hidden forever,
  // with no toggle to open it (the toggle itself is only rendered while
  // `!expanded`). `override` is the user's explicit choice, if any; absent
  // one, `open` tracks `expanded` reactively every render.
  const [override, setOverride] = useState<boolean | null>(null);
  const open = override ?? expanded;
  const m = STEP[step.status] ?? STEP.pending!;
  const Icon = m.icon;
  const dur = step.finishedAt ? fmtDuration(Date.parse(step.finishedAt) - Date.parse(step.startedAt)) : null;
  const label = STEP_LABEL[step.name] ?? step.name;
  const helpId = STEP_HELP[step.name];
  // Task 4: a skipped step's reason (e.g. "disabled in settings") is shown
  // inline and muted, with no toggle — it's already a settled outcome, not
  // something worth a click to reveal.
  const skipped = step.status === 'skipped';
  return (
    <li className="grid gap-1">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Icon className={cn('size-4', m.cls)} aria-hidden />
        <span className="sr-only">{m.label}:</span>
        <span className={step.status === 'failed' ? 'font-semibold' : undefined}>{label}</span>
        {helpId && <HelpTip id={helpId} />}
        {dur && <span className="text-xs text-ink-muted">{dur}</span>}
        {step.message && !skipped && !expanded && (
          <Button variant="link" size="sm" className="h-auto px-0" aria-expanded={open} onClick={() => setOverride(!open)}>
            {open ? 'Hide details' : 'Details'}
          </Button>
        )}
      </div>
      {step.message && skipped && <p className="ml-6 text-xs text-ink-muted">{step.message}</p>}
      {step.message && !skipped && open && <p className="ml-6 whitespace-pre-wrap font-mono text-xs text-ink-muted">{step.message}</p>}
      {extra && <div className="ml-6">{extra}</div>}
    </li>
  );
}

export function AttemptLogViewer({
  attempt,
  defaultOpen = false,
  renderStepExtra,
}: {
  attempt: Attempt;
  defaultOpen?: boolean;
  /** Extra content under a step row (e.g. the rate-ledger usage panel under
   * a failed `rate_ledger` step) — the caller decides which step, if any. */
  renderStepExtra?: (step: AttemptStep) => ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [logOpen, setLogOpen] = useState(false);
  const [filter, setFilter] = useState('');
  // Fix round 1 (review, Important): an unguarded navigator.clipboard.writeText
  // throws outright when the Clipboard API is missing (a plain-http LAN
  // deployment, or a browser that refuses it) and otherwise leaves a
  // rejected promise unhandled — same guard/status pattern as CopyField.
  const [copyLogStatus, setCopyLogStatus] = useState<'idle' | 'copied' | 'failed'>('idle');
  useEffect(() => {
    if (copyLogStatus === 'idle') return;
    const t = window.setTimeout(() => setCopyLogStatus('idle'), 1500);
    return () => window.clearTimeout(t);
  }, [copyLogStatus]);
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
            <StepRow key={`${s.name}-${i}`} step={s} expanded={i === failing} extra={renderStepExtra?.(s)} />
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
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  try {
                    if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
                    await navigator.clipboard.writeText(attempt.log);
                    setCopyLogStatus('copied');
                  } catch {
                    setCopyLogStatus('failed');
                  }
                }}
              >
                {copyLogStatus === 'copied' && <Check className="size-4 text-valid" aria-hidden />}
                {copyLogStatus === 'failed' && <TriangleAlert className="size-4 text-failed" aria-hidden />}
                {copyLogStatus === 'idle' && <Copy className="size-4" aria-hidden />}
                Copy log
              </Button>
              <span aria-live="polite" className="sr-only">
                {copyLogStatus === 'copied' && 'Copied'}
                {copyLogStatus === 'failed' && 'Copy failed'}
              </span>
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
