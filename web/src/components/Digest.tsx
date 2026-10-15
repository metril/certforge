import { Check, Copy, TriangleAlert } from 'lucide-react';
import { IconButton } from '@/components/IconButton';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { diffRuns } from '@/lib/clientStatus';
import { useCopy } from '@/lib/useCopy';
import { cn } from '@/lib/utils';

type Entry = { label: string; value: string; copyLabel?: string };

/** Hex in 8-character groups (thin space between) with the characters that
 * differ from `other` marked. The copied value stays the raw digest. */
function Grouped({ value, other }: { value: string; other?: string }) {
  const runs = other === undefined ? [{ text: value, diff: false }] : diffRuns(value, other);
  const flags = runs.flatMap((r) => Array.from(r.text, () => r.diff));
  const chunks: { text: string; diff: boolean }[][] = [];
  for (let i = 0; i < value.length; i += 8) {
    const chunk: { text: string; diff: boolean }[] = [];
    for (let j = i; j < Math.min(i + 8, value.length); j++) {
      const last = chunk[chunk.length - 1];
      if (last && last.diff === flags[j]) last.text += value[j];
      else chunk.push({ text: value[j]!, diff: !!flags[j] });
    }
    chunks.push(chunk);
  }
  return (
    <>
      {chunks.map((chunk, i) => (
        <span key={i}>
          {i > 0 && ' '}
          {chunk.map((r, k) =>
            r.diff ? (
              <mark key={k} className="rounded-sm bg-drift/20 text-ink">
                {r.text}
              </mark>
            ) : (
              r.text
            ),
          )}
        </span>
      ))}
    </>
  );
}

function DigestRow({ entry, other }: { entry: Entry; other?: string }) {
  const { status, copy } = useCopy(entry.value);
  return (
    <div className="grid gap-0.5">
      <span className="text-xs text-ink-muted">{entry.label}</span>
      <div className="flex items-start gap-1">
        <code className="min-w-0 flex-1 break-all font-mono text-xs">
          <Grouped value={entry.value} other={other} />
        </code>
        <IconButton type="button" variant="ghost" size="icon" className="size-7 shrink-0" label={entry.copyLabel ?? `Copy ${entry.label}`} onClick={() => void copy()}>
          {status === 'copied' && <Check className="size-3.5 text-valid" aria-hidden />}
          {status === 'failed' && <TriangleAlert className="size-3.5 text-failed" aria-hidden />}
          {status === 'idle' && <Copy className="size-3.5" aria-hidden />}
        </IconButton>
        <span aria-live="polite" className="sr-only">
          {status === 'copied' && 'Copied'}
          {status === 'failed' && 'Copy failed'}
        </span>
      </div>
    </div>
  );
}

/**
 * A digest shown in full when it fits, else with a middle ellipsis that keeps
 * the last 8 characters. A click popover shows it whole, with copy and, given
 * `compare`, the characters that differ from the other digest marked.
 */
export function Digest({ value, label, tone, compare }: { value: string | null; label: string; tone?: 'drift'; compare?: { label: string; value: string | null } }) {
  if (!value) return <span className="text-ink-muted">–</span>;
  const own = { label: label.charAt(0).toUpperCase() + label.slice(1), value, copyLabel: `Copy ${label}` };
  const other = compare?.value ? { label: compare.label, value: compare.value, copyLabel: `Copy ${compare.label.toLowerCase()} digest` } : undefined;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={`Show ${label}`}
          className={cn('flex w-full min-w-0 rounded-sm text-left font-mono text-xs outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring', tone === 'drift' ? 'text-drift' : 'text-ink-muted')}
        >
          <span className="truncate">{value.slice(0, -8)}</span>
          <span className="shrink-0">{value.slice(-8)}</span>
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 max-w-[calc(100vw-2rem)] p-2">
        <div className="grid max-h-60 gap-2 overflow-y-auto">
          <DigestRow entry={own} other={other?.value} />
          {other && <DigestRow entry={other} other={value} />}
        </div>
      </PopoverContent>
    </Popover>
  );
}
