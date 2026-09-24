import { useState } from 'react';
import { Lock } from 'lucide-react';
import { UNCHANGED } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type Props = {
  id: string;
  value: string | undefined;
  onChange: (v: string | undefined) => void;
  stored: boolean;
  placeholder?: string;
};

/**
 * Write-only secret field. `stored` says whether THIS field already has a
 * value on the server — callers derive it per field from
 * `storedSecrets: string[]` on the parent record (controller ruling: no
 * global "has secrets" boolean). When stored and untouched, emits UNCHANGED;
 * never emits "".
 */
export function SecretInput({ id, value, onChange, stored, placeholder }: Props) {
  const [editing, setEditing] = useState(!stored);
  if (stored && !editing) {
    return (
      <div className="flex h-9 items-center gap-2">
        <span id={id} className="inline-flex h-6 items-center gap-1 rounded-sm bg-subtle px-2 text-xs font-semibold">
          <Lock className="size-3.5 text-ink-muted" aria-hidden />
          Stored
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
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
        aria-label="New value"
        autoComplete="new-password"
        className="font-mono text-xs"
        placeholder={placeholder}
        value={value === UNCHANGED ? '' : (value ?? '')}
        onChange={(e) => {
          const v = e.target.value;
          onChange(v === '' ? (stored ? UNCHANGED : undefined) : v);
        }}
      />
      {stored && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
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
