import { Fragment, type MouseEvent, type ReactNode } from 'react';
import { useRouter } from '@tanstack/react-router';
import { CircleAlert } from 'lucide-react';
import type { Source } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { HelpKey } from '@/lib/help';

export type ChainEntry = { level: string; value: ReactNode };
const SOURCE_LABEL: Record<Source, string> = { default: 'Built-in', global: 'Global', org: 'Organization', cert: 'Certificate' };
const LEVELS: Source[] = ['default', 'global', 'org', 'cert'];
/** Where each editable level's value is edited, when it is not the current form. */
export type LevelLinks = Partial<Record<'global' | 'org' | 'cert', string>>;

type Props<T> = {
  id: string;
  label: string;
  help?: HelpKey;
  value: T | null | undefined;
  inherited: { value: T | null | undefined; source: Source };
  chain?: ChainEntry[];
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
              {c.level}: {c.value}
            </div>
          ))
        ) : source === 'default' ? (
          'Built-in (shipped with CertForge)'
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

/** One line: Built-in → Global → Organization → Certificate, the level in effect emphasised. */
export function LevelChain({ effective, level, links }: { effective: Source; level?: 'global' | 'org' | 'cert'; links?: LevelLinks }) {
  return (
    <span aria-label="Defaults chain" className="inline-flex flex-wrap items-center gap-x-1 text-xs text-ink-muted">
      {LEVELS.map((l, i) => {
        const href = l !== 'default' && l !== level ? links?.[l] : undefined;
        const label = SOURCE_LABEL[l];
        return (
          <Fragment key={l}>
            {i > 0 && <span aria-hidden>→</span>}
            <span className={l === effective ? 'font-semibold text-foreground' : undefined} aria-current={l === effective ? 'true' : undefined}>
              {href ? <LevelLink href={href}>{label}</LevelLink> : label}
            </span>
          </Fragment>
        );
      })}
    </span>
  );
}

export function InheritableField<T>({ id, label, help, value, inherited, chain, level, links, initial, display, editor, onChange, error, overrideDisabled, pending }: Props<T>) {
  const overridden = value !== null && value !== undefined;
  const switchDisabled = !overridden && !!overrideDisabled;
  const inheritedView = pending ? (
    <span className="text-ink-muted">Inherited after save</span>
  ) : inherited.value === null || inherited.value === undefined ? (
    <span className="text-ink-muted">shipped default</span>
  ) : (
    display(inherited.value)
  );
  // After a reset the value falls to the next level down: the effective source
  // when it is below this form's level, else the level just below it.
  const levelIdx = level ? LEVELS.indexOf(level) : -1;
  const next: Source = levelIdx < 0 || LEVELS.indexOf(inherited.source) < levelIdx ? inherited.source : (LEVELS[Math.max(levelIdx - 1, 0)] as Source);
  const effective: Source = overridden ? (level ?? 'cert') : inherited.source;
  return (
    <div role="group" aria-labelledby={`${id}-label`} className="grid gap-2 border-b border-border py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span id={`${id}-label`} className="text-sm font-semibold">
          {label}
        </span>
        {help && <HelpTip id={help} />}
        <LevelChain effective={effective} level={level} links={links} />
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
