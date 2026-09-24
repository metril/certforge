import { useEffect, useState } from 'react';
import { Lock } from 'lucide-react';
import { UNCHANGED } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type Props = {
  id: string;
  /** The field's own name (e.g. "API token"), used for every accessible name this control produces. */
  label: string;
  value: string | undefined;
  onChange: (v: string | undefined) => void;
  stored: boolean;
  placeholder?: string;
};

/**
 * Write-only secret field. `stored` says whether THIS field already has a
 * value on the server — callers derive it per field from
 * `storedSecrets: string[]` on the parent record (controller ruling: no
 * global "has secrets" boolean). When stored and untouched, emits UNCHANGED
 * on its own (review round 1: a caller that starts with `undefined` must
 * not silently omit the key and erase the secret on PUT); never emits "".
 */
export function SecretInput({ id, label, value, onChange, stored, placeholder }: Props) {
  const [editing, setEditing] = useState(!stored);

  // `stored` flipping (mount, or a parent record reloading with a secret it
  // didn't have before) re-enters stored/"keep it" mode.
  useEffect(() => {
    setEditing(!stored);
  }, [stored]);

  // Proactively emit the sentinel whenever we're showing "Stored" and
  // untouched, instead of relying on the caller to have seeded it.
  useEffect(() => {
    if (stored && !editing && value !== UNCHANGED) onChange(UNCHANGED);
  }, [stored, editing, value, onChange]);

  if (stored && !editing) {
    return (
      <div className="flex h-9 items-center gap-2">
        <span className="inline-flex h-6 items-center gap-1 rounded-sm bg-subtle px-2 text-xs font-semibold">
          <Lock className="size-3.5 text-ink-muted" aria-hidden />
          Stored
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label={`Replace ${label}`}
          onClick={() => {
            setEditing(true);
            onChange(UNCHANGED);
          }}
        >
          Replace
        </Button>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <Input
        id={id}
        type="password"
        aria-label={label}
        aria-describedby={`${id}-hint`}
        autoComplete="new-password"
        className="font-mono text-xs"
        placeholder={placeholder}
        value={value === UNCHANGED ? '' : (value ?? '')}
        onChange={(e) => {
          const v = e.target.value;
          onChange(v === '' ? (stored ? UNCHANGED : undefined) : v);
        }}
      />
      <span id={`${id}-hint`} className="sr-only">
        New value
      </span>
      {stored && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          aria-label={`Keep stored ${label}`}
          onClick={() => {
            setEditing(false);
            onChange(UNCHANGED);
          }}
        >
          Keep stored
        </Button>
      )}
    </div>
  );
}
