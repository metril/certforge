import { useRef, useState } from 'react';
import { Plus, X } from 'lucide-react';
import type { FieldProps } from '@rjsf/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { IconButton } from '@/components/IconButton';

const MAX_HEADERS = 20;

type Row = { id: number; name: string; value: string };

function rowsOf(formData: unknown): Row[] {
  const value = (formData ?? {}) as Record<string, string>;
  return Object.entries(value).map(([name, value_], i) => ({ id: i, name, value: value_ }));
}

function toObject(rows: Row[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) if (r.name.trim() !== '') out[r.name] = r.value;
  return out;
}

/** The names that appear on more than one row, compared case-insensitively
 * (HTTP header names are) — an empty in-progress name never counts. */
function duplicateNames(rows: Row[]): string[] {
  const seen = new Map<string, number>();
  for (const r of rows) {
    const k = r.name.trim().toLowerCase();
    if (k !== '') seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  return [...seen].filter(([, n]) => n > 1).map(([k]) => k);
}

/**
 * Extra-headers editor for the webhook notifier's `headers` field
 * (uiSchema.ts routes any patternProperties-keyed object here via
 * `ui:field: 'headers'`): rows of name/value inputs, an Add header button
 * (disabled at the schema's own `maxProperties`, 20), and a remove icon per
 * row. Rows are local state (row identity by a stable counter, not by name)
 * so two rows can share an in-progress empty or duplicate name while being
 * typed; a row with an empty name is dropped from the emitted object rather
 * than sent as a real header. Duplicate names (case-insensitive) show an
 * inline error and emit `null` instead of an object, so the form's own
 * validation (type: object) fails and blocks the save.
 */
export function HeadersField({ fieldPathId, formData, onChange, disabled, readonly }: FieldProps) {
  const [rows, setRows] = useState<Row[]>(() => rowsOf(formData));
  const nextId = useRef(rows.length);
  const off = disabled || readonly;
  const dupes = duplicateNames(rows);

  function commit(next: Row[]) {
    setRows(next);
    onChange(duplicateNames(next).length > 0 ? null : toObject(next), fieldPathId.path);
  }

  return (
    <div className="grid gap-2">
      {dupes.length > 0 && (
        <p role="alert" className="text-xs text-failed">
          Duplicate header name: {dupes.join(', ')}. Header names are case-insensitive.
        </p>
      )}
      {rows.map((r, i) => (
        <div key={r.id} className="flex items-center gap-1.5">
          <Input
            aria-label={`Header ${i + 1} name`}
            placeholder="Name"
            className="font-mono text-xs"
            value={r.name}
            disabled={off}
            onChange={(e) => commit(rows.map((row) => (row.id === r.id ? { ...row, name: e.target.value } : row)))}
          />
          <Input
            aria-label={`Header ${i + 1} value`}
            placeholder="Value"
            className="font-mono text-xs"
            value={r.value}
            disabled={off}
            onChange={(e) => commit(rows.map((row) => (row.id === r.id ? { ...row, value: e.target.value } : row)))}
          />
          <IconButton
            type="button"
            variant="ghost"
            size="icon-sm"
            label={`Remove header ${i + 1}`}
            disabled={off}
            onClick={() => commit(rows.filter((row) => row.id !== r.id))}
          >
            <X className="size-3.5" aria-hidden />
          </IconButton>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-fit"
        disabled={off || rows.length >= MAX_HEADERS}
        onClick={() => commit([...rows, { id: nextId.current++, name: '', value: '' }])}
      >
        <Plus className="size-3.5" aria-hidden />
        Add header
      </Button>
    </div>
  );
}
