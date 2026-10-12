import { useEffect, useRef, useState } from 'react';
import { KeyRound, Plus, X } from 'lucide-react';
import type { FieldProps } from '@rjsf/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Combobox, type ComboOption } from '@/components/Combobox';
import { HelpTip } from '@/components/HelpTip';
import { IconButton } from '@/components/IconButton';
import { help } from '@/lib/help';
import { cn } from '@/lib/utils';

type File_ = { path: string; content: string; mode?: string };
type Row = { id: number; path: string; content: string; mode: string };
type Cell = 'path' | 'content' | 'mode';

const MAX_FILES = 16;
const CANON: ComboOption[] = [
  { value: 'fullchain', label: 'fullchain', hint: 'Leaf + chain' },
  { value: 'cert', label: 'cert', hint: 'Leaf only' },
  { value: 'chain', label: 'chain', hint: 'Issuers only' },
  { value: 'key', label: 'key', hint: 'Private key' },
  { value: 'bundle', label: 'bundle', hint: 'Fullchain + key' },
];
const CANON_NAMES = CANON.map((o) => o.value);

// Mirrors sshFilesNeedKey in internal/deploy: key, bundle, or any file name from a layout.
const needsKey = (content: string) => content === 'key' || content === 'bundle' || (content !== '' && !['fullchain', 'cert', 'chain'].includes(content));

function rowsOf(formData: unknown, nextId: { current: number }): Row[] {
  const list = Array.isArray(formData) ? (formData as File_[]) : [];
  if (list.length === 0) return [{ id: nextId.current++, path: '', content: 'fullchain', mode: '0644' }];
  return list.map((f) => ({ id: nextId.current++, path: f.path ?? '', content: f.content ?? '', mode: f.mode ?? '' }));
}

function toFiles(rows: Row[]): File_[] {
  return rows.map(({ path, content, mode }) => ({ path, content, ...(mode !== '' ? { mode } : {}) }));
}

/** Server 422s arrive as `files[1].path: ...` messages on the field itself. */
function serverErrors(errors: string[] | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of errors ?? []) {
    const hit = /files\[(\d+)\]\.(path|content|mode)/.exec(m);
    if (hit) out.set(`${hit[1]}.${hit[2]}`, m.replace(/^.*?files\[\d+\]\.(path|content|mode):?\s*/, ''));
  }
  return out;
}

/**
 * Structured editor for the SSH target's `files` (uiSchema.ts routes an array
 * of {path, content, mode} objects here via `ui:field: 'sshFiles'`): a row per
 * file with a remote path, a content picker (certificate part or a layout file
 * name) and an octal mode.
 */
export function SshFilesField({ fieldPathId, formData, onChange, disabled, readonly, schema, uiSchema, errorSchema, rawErrors, registry }: FieldProps) {
  const nextId = useRef(0);
  const [rows, setRows] = useState<Row[]>(() => rowsOf(formData, nextId));
  // The last value this field emitted: a different formData came from outside (Discard).
  const emitted = useRef(JSON.stringify(formData));
  useEffect(() => {
    if (JSON.stringify(formData) === emitted.current) return;
    emitted.current = JSON.stringify(formData);
    setRows(rowsOf(formData, nextId));
  }, [formData]);
  if (uiSchema?.['ui:widget'] === 'hidden') return null;

  const off = disabled || readonly;
  const max = typeof schema.maxItems === 'number' ? schema.maxItems : MAX_FILES;
  const names = ((registry.formContext as { sshContentNames?: { name: string; layout: string }[] } | undefined)?.sshContentNames ?? []).filter((n) => !CANON_NAMES.includes(n.name));
  const options: ComboOption[] = [...CANON, ...names.map((n) => ({ value: n.name, label: n.name, hint: `Layout: ${n.layout}` }))];
  const server = serverErrors(rawErrors);
  const unmatched = (rawErrors ?? []).filter((m) => !/files\[\d+\]\.(path|content|mode)/.test(m));

  function commit(next: Row[]) {
    setRows(next);
    const out = toFiles(next);
    emitted.current = JSON.stringify(out);
    onChange(out, fieldPathId.path);
  }
  const patch = (id: number, p: Partial<Row>) => commit(rows.map((r) => (r.id === id ? { ...r, ...p } : r)));
  const errorOf = (i: number, cell: Cell): string | undefined => {
    const client = (errorSchema as Record<string, { [c: string]: { __errors?: string[] } } | undefined> | undefined)?.[i]?.[cell]?.__errors?.[0];
    return client ?? server.get(`${i}.${cell}`);
  };
  const GRID = 'grid grid-cols-[minmax(0,1fr)_10rem_4.5rem_auto] gap-1.5 items-start';

  return (
    <div className="grid gap-2">
      <div className={cn(GRID, 'text-xs text-ink-muted')}>
        <span>Remote path</span>
        <span className="inline-flex items-center gap-1">
          Content <HelpTip id="sshFiles.content" label="Content" />
        </span>
        <span>Mode</span>
        <span className="w-8" />
      </div>
      {rows.map((r, i) => {
        const cellErrors = (['path', 'content', 'mode'] as const).map((c) => errorOf(i, c));
        const firstError = cellErrors.find(Boolean);
        return (
          <div key={r.id} className="grid gap-1">
            <div className={GRID}>
              <Input
                aria-label={`File ${i + 1} remote path`}
                aria-invalid={cellErrors[0] ? true : undefined}
                className="font-mono text-xs"
                placeholder="/etc/ssl/certs/site.pem"
                value={r.path}
                disabled={off}
                onChange={(e) => patch(r.id, { path: e.target.value })}
              />
              <div className="flex items-center gap-1">
                <Combobox
                  mono
                  creatable
                  aria-label={`File ${i + 1} content`}
                  aria-invalid={cellErrors[1] ? true : undefined}
                  value={r.content}
                  onChange={(v) => patch(r.id, { content: v ?? '' })}
                  options={options}
                  placeholder="Content"
                  emptyText="No match."
                  disabled={off}
                />
                {needsKey(r.content) && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span role="img" aria-label="Needs the private key" tabIndex={0} className="inline-flex rounded-sm bg-subtle px-1 text-xs">
                        <KeyRound className="size-3.5" aria-hidden />
                      </span>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-64">{help['sshFiles.needsKey'].text}</TooltipContent>
                  </Tooltip>
                )}
              </div>
              <Input
                aria-label={`File ${i + 1} mode`}
                aria-invalid={cellErrors[2] ? true : undefined}
                className="font-mono text-xs"
                placeholder="0644"
                maxLength={4}
                value={r.mode}
                disabled={off}
                onChange={(e) => patch(r.id, { mode: e.target.value })}
              />
              <IconButton
                type="button"
                variant="ghost"
                size="icon"
                className="size-9"
                label={`Remove file ${i + 1}`}
                disabled={off || rows.length <= 1}
                onClick={() => commit(rows.filter((row) => row.id !== r.id))}
              >
                <X className="size-4" aria-hidden />
              </IconButton>
            </div>
            {firstError && <p className="text-xs text-failed">{firstError}</p>}
          </div>
        );
      })}
      {unmatched.map((m) => (
        <p key={m} className="text-xs text-failed">
          {m}
        </p>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-fit"
        disabled={off || rows.length >= max}
        onClick={() => commit([...rows, { id: nextId.current++, path: '', content: 'fullchain', mode: '0644' }])}
      >
        <Plus className="size-3.5" aria-hidden />
        Add file
      </Button>
    </div>
  );
}
