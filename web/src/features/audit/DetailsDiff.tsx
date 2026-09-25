import { useState } from 'react';
import { ChevronRight, Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const show = (v: unknown) => (v === undefined ? undefined : JSON.stringify(v));

export type DiffRow = { key: string; before?: string; after?: string; kind: 'added' | 'removed' | 'changed' };

/** Field-level diff of details.before and details.after; null when absent. */
export function diffDetails(details: Obj): { rows: DiffRow[]; rest: Obj } | null {
  if (!isObj(details.before) && !isObj(details.after)) return null;
  const before = isObj(details.before) ? details.before : {};
  const after = isObj(details.after) ? details.after : {};
  const rows: DiffRow[] = [];
  for (const key of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
    const b = show(before[key]);
    const a = show(after[key]);
    if (b === a) continue;
    rows.push({ key, before: b, after: a, kind: b === undefined ? 'added' : a === undefined ? 'removed' : 'changed' });
  }
  const rest = Object.fromEntries(Object.entries(details).filter(([k]) => k !== 'before' && k !== 'after'));
  return { rows, rest };
}

function Json({ value, label }: { value: Obj; label: string }) {
  const [open, setOpen] = useState(false);
  const text = JSON.stringify(value, null, 2);
  return (
    <div className="grid gap-1">
      <button
        type="button"
        className="flex items-center gap-1 text-xs text-ink-muted hover:text-ink"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <ChevronRight className={`size-3.5 transition-transform ${open ? 'rotate-90' : ''}`} aria-hidden />
        {label}
      </button>
      {open && (
        <div className="relative">
          <pre className="max-h-80 overflow-auto rounded-md border border-border bg-surface p-3 pr-9 font-mono text-xs">{text}</pre>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="absolute right-1 top-1"
            aria-label="Copy JSON"
            onClick={() => void navigator.clipboard.writeText(text)}
          >
            <Copy className="size-3.5" aria-hidden />
          </Button>
        </div>
      )}
    </div>
  );
}

export function DetailsDiff({ details }: { details: Obj }) {
  const diff = diffDetails(details);
  if (!diff) return <Json value={details} label="Raw details" />;
  return (
    <div className="grid gap-3">
      <table aria-label="Changes" className="w-full table-fixed text-xs">
        <thead>
          <tr className="border-b border-border text-left text-ink-muted">
            <th className="w-32 py-1 font-normal">Field</th>
            <th className="py-1 font-normal">Before</th>
            <th className="py-1 font-normal">After</th>
          </tr>
        </thead>
        <tbody>
          {diff.rows.map((r) => (
            <tr key={r.key} className="border-b border-border align-top">
              <td className="py-1 font-mono">{r.key}</td>
              <td className="break-all py-1 font-mono text-ink-muted line-through">{r.before ?? '–'}</td>
              <td className="break-all py-1 font-mono">{r.after ?? '–'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {diff.rows.length === 0 && <p className="text-sm text-ink-muted">No field changed.</p>}
      {Object.keys(diff.rest).length > 0 && <Json value={diff.rest} label="Other details" />}
    </div>
  );
}
