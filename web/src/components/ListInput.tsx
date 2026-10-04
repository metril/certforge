import { useId, useState } from 'react';
import { CircleAlert, X } from 'lucide-react';
import { cn } from '@/lib/utils';

type Props = {
  id?: string;
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  'aria-label'?: string;
  validate?: (item: string) => string | null;
  disabled?: boolean;
};

export function ListInput({ id, value, onChange, placeholder, validate, disabled, ...rest }: Props) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const errorId = `${inputId}-error`;
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);

  function commit(text: string) {
    const items = text
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const bad = validate ? items.map(validate).find((e) => e) : null;
    if (bad) {
      setError(bad);
      return;
    }
    setError(null);
    const next = [...value];
    for (const item of items) if (!next.includes(item)) next.push(item);
    onChange(next);
    setDraft('');
  }

  return (
    <div className="grid gap-1">
      <div className={cn('flex min-h-9 flex-wrap items-center gap-1 rounded-md border border-input bg-field px-1.5 py-1 transition-[color,box-shadow] hover:border-ink-muted focus-within:border-primary focus-within:ring-2 focus-within:ring-ring/40', disabled && 'opacity-60')}>
        {value.map((v) => (
          <span key={v} className="inline-flex h-6 items-center gap-1 rounded-sm bg-subtle pl-2 pr-1 font-mono text-xs">
            {v}
            {!disabled && (
              <button
                type="button"
                aria-label={`Remove ${v}`}
                onClick={() => onChange(value.filter((x) => x !== v))}
                className="rounded-sm p-0.5 hover:bg-border"
              >
                <X className="size-3" aria-hidden />
              </button>
            )}
          </span>
        ))}
        <input
          id={inputId}
          aria-label={rest['aria-label']}
          aria-describedby={error ? errorId : undefined}
          aria-invalid={!!error}
          value={draft}
          disabled={disabled}
          placeholder={value.length ? undefined : placeholder}
          className="h-6 min-w-24 flex-1 bg-transparent font-mono text-xs outline-none disabled:cursor-not-allowed"
          onChange={(e) => {
            setDraft(e.target.value);
            // A stale error from a previous rejected entry shouldn't keep
            // showing once the operator starts fixing it.
            if (error) setError(null);
          }}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ',') && draft.trim()) {
              e.preventDefault();
              commit(draft);
            } else if (e.key === 'Backspace' && !draft && value.length) {
              onChange(value.slice(0, -1));
            }
          }}
          onBlur={() => draft.trim() && commit(draft)}
          onPaste={(e) => {
            const text = e.clipboardData.getData('text/plain');
            if (/[\s,]/.test(text)) {
              e.preventDefault();
              const { selectionStart: a, selectionEnd: b } = e.currentTarget;
              commit(draft.slice(0, a ?? draft.length) + text + draft.slice(b ?? draft.length));
            }
          }}
        />
      </div>
      {error && (
        <p id={errorId} role="alert" className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          {error}
        </p>
      )}
    </div>
  );
}
