import { useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowUp, CircleAlert, Plus, X } from 'lucide-react';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { IconButton } from '@/components/IconButton';

const MAX_ARGV = 64;
const MAX_ARG_BYTES = 4096;
const byteLength = (s: string) => new TextEncoder().encode(s).length;

/** Mirrors delivery.ValidateHook/CleanPath (internal/delivery/hooks.go,
 * delivery.go) exactly: argv[0] must be an absolute, already-clean path —
 * no ./.. segments, no trailing or repeated slash, not "/" alone — since
 * the agent compares it byte-for-byte with its CF_HOOK_ALLOW entries.
 * Every argv entry (including argv[0]) is capped at 4096 bytes and may
 * not contain a NUL byte. Arguments after argv[0] carry no other
 * restriction: the server accepts spaces and empty strings there, since a
 * hook is exec'd directly and never runs through a shell. */
export function argvErrors(argv: string[]): (string | null)[] {
  return argv.map((a, i) => {
    if (i === 0) {
      if (!a) return 'Enter the executable path.';
      if (!a.startsWith('/')) return 'Use an absolute path.';
      const segments = a.slice(1).split('/');
      if (a === '/' || a.endsWith('/') || segments.some((s) => s === '' || s === '.' || s === '..')) {
        return 'Use a clean path: no . or .. segments, no trailing or repeated slash.';
      }
    }
    if (a.includes('\0')) return 'Remove the embedded NUL character.';
    if (byteLength(a) > MAX_ARG_BYTES) return 'Keep it to at most 4096 bytes.';
    return null;
  });
}

type Props = { id: string; value: string[]; onChange: (v: string[]) => void; errors?: (string | null)[]; disabled?: boolean };

export function ArgvField({ id, value, onChange, errors = [], disabled = false }: Props) {
  const argv = value.length ? value : [''];
  const idSeq = useRef(0);
  const makeRowId = () => `r${idSeq.current++}`;
  const [rowIds, setRowIds] = useState<string[]>(() => argv.map(() => makeRowId()));
  // Index to focus once the DOM has caught up with a move/remove — a
  // moved or removed row's own control can become disabled (e.g. row 1's
  // "Move up") or vanish outright, and a browser drops focus to <body> in
  // both cases unless something else claims it first.
  const [focusIndex, setFocusIndex] = useState<number | null>(null);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (focusIndex === null) return;
    inputRefs.current[focusIndex]?.focus();
    setFocusIndex(null);
  }, [focusIndex]);

  const set = (i: number, v: string) => onChange(argv.map((a, j) => (j === i ? v : a)));

  const move = (i: number, d: -1 | 1) => {
    const next = [...argv];
    [next[i], next[i + d]] = [next[i + d]!, next[i]!];
    onChange(next);
    setRowIds((ids) => {
      const n = [...ids];
      [n[i], n[i + d]] = [n[i + d]!, n[i]!];
      return n;
    });
    setFocusIndex(i + d);
  };

  const remove = (i: number) => {
    onChange(argv.filter((_, j) => j !== i));
    setRowIds((ids) => ids.filter((_, j) => j !== i));
    setFocusIndex(Math.min(i, argv.length - 2));
  };

  const add = () => {
    onChange([...argv, '']);
    setRowIds((ids) => [...ids, makeRowId()]);
    setFocusIndex(argv.length);
  };

  return (
    <div className="grid gap-2">
      <ol aria-label="Command" className="grid gap-2">
        {argv.map((a, i) => {
          const inputId = `${id}-${i}`;
          const label = i === 0 ? 'Executable' : `Argument ${i}`;
          const rowKey = rowIds[i] ?? `${i}`;
          return (
            <li key={rowKey} className="grid gap-1 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-center sm:gap-2">
              <span className="flex items-center gap-1.5">
                <Label htmlFor={inputId} className="text-xs text-ink-muted">
                  {label}
                </Label>
                {i === 0 && <HelpTip id="hook.allowlist" warning />}
              </span>
              <div className="flex min-w-0 items-center gap-1">
                <Input
                  id={inputId}
                  ref={(el) => {
                    inputRefs.current[i] = el;
                  }}
                  className="min-w-0 flex-1 font-mono text-xs"
                  placeholder={i === 0 ? '/usr/sbin/nginx' : i === 1 ? '-s' : 'reload'}
                  value={a}
                  disabled={disabled}
                  aria-invalid={errors[i] ? true : undefined}
                  onChange={(e) => set(i, e.target.value)}
                />
                {i > 0 && !disabled && (
                  <>
                    <IconButton type="button" variant="ghost" size="icon-sm" className="size-7" label={`Move argument ${i} up`} disabled={i === 1} onClick={() => move(i, -1)}>
                      <ArrowUp className="size-3.5" aria-hidden />
                    </IconButton>
                    <IconButton type="button" variant="ghost" size="icon-sm" className="size-7" label={`Move argument ${i} down`} disabled={i === argv.length - 1} onClick={() => move(i, 1)}>
                      <ArrowDown className="size-3.5" aria-hidden />
                    </IconButton>
                    <IconButton type="button" variant="ghost" size="icon-sm" className="size-7" label={`Remove argument ${i}`} onClick={() => remove(i)}>
                      <X className="size-3.5" aria-hidden />
                    </IconButton>
                  </>
                )}
              </div>
              {errors[i] && (
                <p role="alert" className="flex items-center gap-1 text-xs sm:col-start-2">
                  <CircleAlert className="size-3.5 text-failed" aria-hidden />
                  {errors[i]}
                </p>
              )}
            </li>
          );
        })}
      </ol>
      {!disabled && (
        <Button type="button" variant="outline" size="sm" className="w-fit" disabled={argv.length >= MAX_ARGV} onClick={add}>
          <Plus className="size-4" aria-hidden />
          Add argument
        </Button>
      )}
    </div>
  );
}
