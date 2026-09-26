import { ArrowDown, ArrowUp, CircleAlert, Plus, X } from 'lucide-react';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const MAX_ARGV = 64;

/** argv[0] must be one absolute path (the agent compares it with its
 * CF_HOOK_ALLOW entries exactly); arguments are passed verbatim, so spaces
 * inside one argument are fine, but an empty row is a mistake. */
export function argvErrors(argv: string[]): (string | null)[] {
  return argv.map((a, i) => {
    if (i > 0) return a === '' ? 'Enter a value or remove this argument.' : null;
    if (!a.trim()) return 'Enter the executable path.';
    if (!a.startsWith('/')) return 'Use an absolute path.';
    if (/\s/.test(a)) return 'One path, no spaces or arguments.';
    return null;
  });
}

type Props = { id: string; value: string[]; onChange: (v: string[]) => void; errors?: (string | null)[]; disabled?: boolean };

export function ArgvField({ id, value, onChange, errors = [], disabled = false }: Props) {
  const argv = value.length ? value : [''];
  const set = (i: number, v: string) => onChange(argv.map((a, j) => (j === i ? v : a)));
  const move = (i: number, d: -1 | 1) => {
    const next = [...argv];
    [next[i], next[i + d]] = [next[i + d]!, next[i]!];
    onChange(next);
  };
  return (
    <div className="grid gap-2">
      <ol aria-label="Command" className="grid gap-2">
        {argv.map((a, i) => {
          const inputId = `${id}-${i}`;
          const label = i === 0 ? 'Executable' : `Argument ${i}`;
          return (
            <li key={i} className="grid gap-1 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-center sm:gap-2">
              <span className="flex items-center gap-1.5">
                <Label htmlFor={inputId} className="text-xs text-ink-muted">
                  {label}
                </Label>
                {i === 0 && <HelpTip id="hook.allowlist" warning />}
              </span>
              <div className="flex min-w-0 items-center gap-1">
                <Input
                  id={inputId}
                  className="min-w-0 flex-1 font-mono text-xs"
                  placeholder={i === 0 ? '/usr/sbin/nginx' : i === 1 ? '-s' : 'reload'}
                  value={a}
                  disabled={disabled}
                  aria-invalid={errors[i] ? true : undefined}
                  onChange={(e) => set(i, e.target.value)}
                />
                {i > 0 && !disabled && (
                  <>
                    <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Move argument ${i} up`} disabled={i === 1} onClick={() => move(i, -1)}>
                      <ArrowUp className="size-3.5" aria-hidden />
                    </Button>
                    <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Move argument ${i} down`} disabled={i === argv.length - 1} onClick={() => move(i, 1)}>
                      <ArrowDown className="size-3.5" aria-hidden />
                    </Button>
                    <Button variant="ghost" size="icon-sm" className="size-7" aria-label={`Remove argument ${i}`} onClick={() => onChange(argv.filter((_, j) => j !== i))}>
                      <X className="size-3.5" aria-hidden />
                    </Button>
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
        <Button variant="outline" size="sm" className="w-fit" disabled={argv.length >= MAX_ARGV} onClick={() => onChange([...argv, ''])}>
          <Plus className="size-4" aria-hidden />
          Add argument
        </Button>
      )}
    </div>
  );
}
