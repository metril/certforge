import { type MouseEvent, type ReactNode } from 'react';
import { useRouter } from '@tanstack/react-router';
import { CircleAlert } from 'lucide-react';
import type { Source } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { HelpKey } from '@/lib/help';

/** One level's value for a field, shown in the source badge's popover. */
export type ChainEntry = { level: Source; value: ReactNode };
const SOURCE_LABEL: Record<Source, string> = { default: 'Global', global: 'Global', org: 'Organization', cert: 'Certificate' };
const LEVELS: Source[] = ['global', 'org', 'cert'];
/** The shipped value is Global's own until an admin changes it, so a default-sourced value belongs to the Global level. */
const norm = (s: Source): Source => (s === 'default' ? 'global' : s);
/** Where each editable level's value is edited, when it is not the current form. */
export type LevelLinks = Partial<Record<'global' | 'org' | 'cert', string>>;

type Props<T> = {
  id: string;
  label: string;
  help?: HelpKey;
  value: T | null | undefined;
  inherited: { value: T | null | undefined; source: Source };
  /** What each other level holds for this field (the edited level's own value is filled in here). */
  chain?: ChainEntry[];
  /** The shipped defaults are not known (loading, or unavailable): a value falling back to them is shown as such, never as "not set". */
  builtinState?: 'loading' | 'error';
  /** What "nothing set anywhere" does for this field, when the built-in is not a value. */
  unsetText?: string;
  /** The level this form edits; it is "here", so it gets no link. */
  level?: 'global' | 'org' | 'cert';
  links?: LevelLinks;
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
              {SOURCE_LABEL[c.level]}: {c.value}
            </div>
          ))
        ) : source === 'default' ? (
          'Global (shipped with CertForge)'
        ) : (
          `Inherited from ${SOURCE_LABEL[source]}`
        )}
      </TooltipContent>
    </Tooltip>
  );
}

function LevelLink({ href, children }: { href: string; children: ReactNode }) {
  const router = useRouter({ warn: false });
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (!router || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    router.history.push(href);
  };
  return (
    <a href={href} onClick={onClick} className="underline underline-offset-2 hover:text-foreground">
      {children}
    </a>
  );
}

const ABSENT: Partial<Record<Source, string>> = { org: 'set per organization', cert: 'set per certificate' };

/** The one source badge: focusable, opens this field's chain with each level's value, the one in effect emphasised and each other editable level linked. */
function FieldSourceBadge({ effective, level, links, entries }: { effective: Source; level?: 'global' | 'org' | 'cert'; links?: LevelLinks; entries: Map<Source, ReactNode> }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button type="button" className="inline-flex h-5 items-center rounded-sm border border-border bg-subtle px-1.5 text-xs hover:bg-selected">
          {SOURCE_LABEL[effective]}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="grid w-auto max-w-80 gap-1 p-3 text-xs">
        {LEVELS.map((l) => {
          const href = l !== level && l !== 'default' ? links?.[l] : undefined;
          const label = SOURCE_LABEL[l];
          const v = entries.get(l) ?? ABSENT[l];
          return (
            <div key={l} aria-current={l === norm(effective) ? 'true' : undefined} className={l === norm(effective) ? 'font-semibold text-foreground' : 'text-ink-muted'}>
              {href ? <LevelLink href={href}>{label}</LevelLink> : label}
              {v != null && <>: {v}</>}
            </div>
          );
        })}
      </PopoverContent>
    </Popover>
  );
}

export function InheritableField<T>({ id, label, help, value, inherited, chain, builtinState, unsetText, level, links, initial, display, editor, onChange, error, overrideDisabled, pending }: Props<T>) {
  const overridden = value !== null && value !== undefined;
  const unknownShipped = (inherited.value === null || inherited.value === undefined) && inherited.source === 'default';
  if (level === 'global') {
    return (
      <BaseField
        {...{ id, label, help, value, inherited, builtinState, unsetText, initial, display, editor, onChange, error, overrideDisabled }}
        unknownShipped={unknownShipped}
      />
    );
  }
  const switchDisabled = !overridden && !!overrideDisabled;
  const inheritedView = pending ? (
    <span className="text-ink-muted">Inherited after save</span>
  ) : (inherited.value === null || inherited.value === undefined) && inherited.source === 'default' && builtinState === 'loading' ? (
    <span role="status" aria-label="Loading default" className="inline-block h-3 w-24 animate-pulse rounded-sm bg-subtle align-middle" />
  ) : (inherited.value === null || inherited.value === undefined) && inherited.source === 'default' && builtinState === 'error' ? (
    <span className="text-ink-muted">Default unavailable</span>
  ) : inherited.value === null || inherited.value === undefined ? (
    <span className="text-ink-muted">{unsetText ?? 'not set'}</span>
  ) : (
    display(inherited.value)
  );
  // After a reset the value falls to the next level down: the effective source
  // when it is below this form's level, else the level just below it.
  const levelIdx = level ? LEVELS.indexOf(level) : -1;
  const next: Source = levelIdx < 0 || LEVELS.indexOf(norm(inherited.source)) < levelIdx ? norm(inherited.source) : (LEVELS[Math.max(levelIdx - 1, 0)] as Source);
  const effective: Source = overridden ? (level ?? 'cert') : inherited.source;
  const entries = new Map<Source, ReactNode>((chain ?? []).map((c) => [norm(c.level), c.value]));
  if (level) entries.set(level, overridden ? display(value as T) : 'not set');
  return (
    <div role="group" aria-labelledby={`${id}-label`} className="grid gap-2 border-b border-border py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span id={`${id}-label`} className="text-sm font-semibold">
          {label}
        </span>
        {help && <HelpTip id={help} />}
        {pending ? (
          <span className="inline-flex h-5 items-center rounded-sm border border-dashed border-border px-1.5 text-xs text-ink-muted">Pending</span>
        ) : (
          <FieldSourceBadge effective={effective} level={level} links={links} entries={entries} />
        )}
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
            {overridden ? 'Set here' : switchDisabled ? overrideDisabled : null}
          </span>
        </div>
      </div>
      {overridden ? (
        <div className="grid gap-1.5">
          <div className="flex flex-wrap items-center gap-3">
            {editor(value as T, (v) => onChange(v))}
            <Button type="button" variant="link" size="sm" className="px-0" onClick={() => onChange(null)}>
              Use {SOURCE_LABEL[next]} value
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
        <div className="text-sm">
          {!pending && <span className="text-ink-muted">Using {SOURCE_LABEL[inherited.source]}: </span>}
          {inheritedView}
        </div>
      )}
    </div>
  );
}

type BaseProps<T> = Pick<Props<T>, 'id' | 'label' | 'help' | 'value' | 'inherited' | 'builtinState' | 'unsetText' | 'initial' | 'display' | 'editor' | 'onChange' | 'error' | 'overrideDisabled'> & { unknownShipped: boolean };

/** A Global field: Global is the base layer, so there is no Override switch. The control shows the stored value, else the value CertForge ships with; Reset removes the stored key. */
function BaseField<T>({ id, label, help, value, inherited, builtinState, unsetText, initial, display, editor, onChange, error, overrideDisabled, unknownShipped }: BaseProps<T>) {
  const stored = value !== null && value !== undefined;
  const shipped = inherited.value as T | null | undefined;
  const hasShipped = shipped !== null && shipped !== undefined;
  const shown = stored ? (value as T) : hasShipped ? shipped : undefined;
  const differs = stored && (!hasShipped || JSON.stringify(value) !== JSON.stringify(shipped));
  void display;
  let body: ReactNode;
  if (shown !== undefined) {
    body = editor(shown, (v) => onChange(v));
  } else if (unknownShipped && builtinState === 'loading') {
    body = <span role="status" aria-label="Loading default" className="inline-block h-3 w-24 animate-pulse rounded-sm bg-subtle align-middle" />;
  } else if (unknownShipped && builtinState === 'error') {
    body = <span className="text-ink-muted">Default unavailable</span>;
  } else {
    body = (
      <>
        <span className="text-sm text-ink-muted">{unsetText ?? 'not set'}</span>
        {overrideDisabled && <span className="text-sm text-ink-muted">({overrideDisabled})</span>}
        {!overrideDisabled && (
          <Button type="button" variant="ghost" size="sm" onClick={() => onChange(initial)}>
            Set
          </Button>
        )}
      </>
    );
  }
  return (
    <div role="group" aria-labelledby={`${id}-label`} className="grid gap-2 border-b border-border py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span id={`${id}-label`} className="text-sm font-semibold">
          {label}
        </span>
        {help && <HelpTip id={help} />}
      </div>
      <div className="grid gap-1.5">
        <div className="flex flex-wrap items-center gap-3">
          {body}
          {differs && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button type="button" variant="ghost" size="sm" onClick={() => onChange(null)}>
                  Reset
                </Button>
              </TooltipTrigger>
              <TooltipContent>Back to the value CertForge ships with</TooltipContent>
            </Tooltip>
          )}
        </div>
        {error && (
          <p role="alert" className="flex items-center gap-1 text-xs">
            <CircleAlert className="size-3.5 text-failed" aria-hidden />
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
