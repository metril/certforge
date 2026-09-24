import type { ReactNode } from 'react';
import { CircleAlert } from 'lucide-react';
import type { Source } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { HelpKey } from '@/lib/help';

export type ChainEntry = { level: string; value: ReactNode };
const SOURCE_LABEL: Record<Source, string> = { default: 'Default', global: 'Global', org: 'Org', cert: 'Cert' };

type Props<T> = {
  id: string;
  label: string;
  help?: HelpKey;
  value: T | null | undefined;
  inherited: { value: T | null | undefined; source: Source };
  chain?: ChainEntry[];
  initial: T;
  display: (v: T) => ReactNode;
  // set accepts null (review fix round 1, #4): an editor whose own clear
  // affordance (Combobox) means "unset", not "set to empty string", calls
  // this the same way "Reset to inherited" does, instead of a 422-guaranteed
  // empty-string value.
  editor: (v: T, set: (v: T | null) => void) => ReactNode;
  onChange: (v: T | null) => void;
  /** A 422 mapped to this field (controller ruling: reference errors show next to the field). */
  error?: string | null;
  /** Disables turning Override on (e.g. an empty CA list has nothing to pick); shown as the state text. An already-overridden field can still be reset. */
  overrideDisabled?: string;
  /** This field was reset to inherited this session but the save hasn't landed yet, so `inherited` (still the last server response) would show a stale value/badge (review fix round 1, #3). */
  pending?: boolean;
};

export function SourceBadge({ source, chain }: { source: Source; chain?: ChainEntry[] }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className="inline-flex h-5 items-center rounded-sm border border-border bg-subtle px-1.5 text-xs">
          {SOURCE_LABEL[source]}
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {chain?.length ? (
          chain.map((c) => (
            <div key={c.level}>
              {c.level}: {c.value}
            </div>
          ))
        ) : source === 'default' ? (
          'Server default'
        ) : (
          `Inherited from ${SOURCE_LABEL[source]}`
        )}
      </TooltipContent>
    </Tooltip>
  );
}

export function InheritableField<T>({ id, label, help, value, inherited, chain, initial, display, editor, onChange, error, overrideDisabled, pending }: Props<T>) {
  const overridden = value !== null && value !== undefined;
  const switchDisabled = !overridden && !!overrideDisabled;
  const inheritedView = pending ? (
    <span className="text-ink-muted">Inherited after save</span>
  ) : inherited.value === null || inherited.value === undefined ? (
    <span className="text-ink-muted">Server default</span>
  ) : (
    display(inherited.value)
  );
  return (
    <div role="group" aria-labelledby={`${id}-label`} className="grid gap-2 border-b border-border py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span id={`${id}-label`} className="text-sm font-semibold">
          {label}
        </span>
        {help && <HelpTip id={help} />}
        {!overridden &&
          (pending ? (
            <span className="inline-flex h-5 items-center rounded-sm border border-dashed border-border px-1.5 text-xs text-ink-muted">Pending</span>
          ) : (
            <SourceBadge source={inherited.source} chain={chain} />
          ))}
        <div className="ml-auto flex items-center gap-2">
          <Label htmlFor={`${id}-override`} className="text-ink-muted">
            Override
          </Label>
          <Switch
            id={`${id}-override`}
            aria-label={`Override ${label}`}
            checked={overridden}
            disabled={switchDisabled}
            onCheckedChange={(on) => onChange(on ? ((inherited.value ?? initial) as T) : null)}
          />
          <span className="text-sm text-ink-muted" aria-hidden>
            {overridden ? 'Overridden' : switchDisabled ? overrideDisabled : 'Inherited'}
          </span>
        </div>
      </div>
      {overridden ? (
        <div className="grid gap-1.5">
          <div className="flex flex-wrap items-center gap-3">
            {editor(value as T, (v) => onChange(v))}
            <Button type="button" variant="link" size="sm" className="px-0" onClick={() => onChange(null)}>
              Reset to inherited
            </Button>
          </div>
          {error && (
            <p role="alert" className="flex items-center gap-1 text-xs">
              <CircleAlert className="size-3.5 text-failed" aria-hidden />
              {error}
            </p>
          )}
        </div>
      ) : (
        <div className="text-sm">{inheritedView}</div>
      )}
    </div>
  );
}
