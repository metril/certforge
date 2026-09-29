import { useRef, useState } from 'react';
import { Plus, X } from 'lucide-react';
import type { FieldProps } from '@rjsf/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

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

/**
 * Extra-headers editor for the webhook notifier's `headers` field
 * (uiSchema.ts routes any patternProperties-keyed object here via
 * `ui:field: 'headers'`): rows of name/value inputs, an Add header button
 * (disabled at the schema's own `maxProperties`, 20), and a remove icon per
 * row. Rows are local state (row identity by a stable counter, not by name)
 * so two rows can share an in-progress empty or duplicate name while being
 * typed; a row with an empty name is dropped from the emitted object rather
 * than sent as a real header.
 */
export function HeadersField({ fieldPathId, formData, onChange, disabled, readonly }: FieldProps) {
  const [rows, setRows] = useState<Row[]>(() => rowsOf(formData));
  const nextId = useRef(rows.length);
  const off = disabled || readonly;

  function commit(next: Row[]) {
    setRows(next);
    onChange(toObject(next), fieldPathId.path);
  }

  return (
    <div className="grid gap-2">
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
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            aria-label={`Remove header ${i + 1}`}
            disabled={off}
            onClick={() => commit(rows.filter((row) => row.id !== r.id))}
          >
            <X className="size-3.5" aria-hidden />
          </Button>
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
