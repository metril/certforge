import { useCallback, useEffect, useRef, useState } from 'react';
import { CircleAlert, Eye, EyeOff, Loader2, Lock } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { UNCHANGED } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

type Props = {
  id: string;
  /** The field's own name (e.g. "API token"), used for every accessible name this control produces. */
  label: string;
  value: string | undefined;
  onChange: (v: string | undefined) => void;
  stored: boolean;
  placeholder?: string;
  disabled?: boolean;
  /** When set, the field's own Remove button renders disabled with a
   * tooltip giving this reason, instead of being removable — never hidden
   * (fix wave: a layout password while any file is p12/jks used to hide
   * Remove outright). Omit to let Remove work normally. */
  removeDisabledReason?: string;
  /** Fetches the stored value's plaintext. Absent: no reveal button. */
  onReveal?: () => Promise<string>;
  /** When set, the reveal button renders disabled with this tooltip. */
  revealDisabledReason?: string;
};

/**
 * Write-only secret field. `stored` says whether THIS field already has a
 * value on the server — callers derive it per field from
 * `storedSecrets: string[]` on the parent record (controller ruling: no
 * global "has secrets" boolean). When stored and untouched, emits UNCHANGED
 * on its own (review round 1: a caller that starts with `undefined` must
 * not silently omit the key and erase the secret on PUT); never emits "".
 * `disabled` (fix round 1: a read-only SchemaForm) drops both the input and
 * the Replace/Keep-stored buttons — there's nothing a disabled field can let
 * the caller do, so it shows only the static "Stored"/"Not set" state.
 */
export function SecretInput({ id, label, value, onChange: onChangeProp, stored, placeholder, disabled = false, removeDisabledReason, onReveal, revealDisabledReason }: Props) {
  // The last value this control itself emitted: a `value` that differs from it
  // and is back at UNCHANGED/undefined was reset from outside (Discard, or a
  // Save that reloaded the record), not typed.
  const emitted = useRef(value);
  const onChange = useCallback(
    (v: string | undefined) => {
      emitted.current = v;
      onChangeProp(v);
    },
    [onChangeProp],
  );
  const [editing, setEditing] = useState(!stored);
  // Fix round 1 (Take now #4): Replace and Remove both start editing with an
  // empty-looking input, but clearing back to "" afterward must mean
  // different things — Replace's "" means "never mind, keep the stored
  // value" (UNCHANGED); Remove's "" means "actually clear it" ("", sent
  // every time, not just on the first keystroke). This flag is what tells
  // the input's own onChange which one the operator asked for.
  const [removed, setRemoved] = useState(false);
  const [shown, setShown] = useState(false);
  // The revealed plaintext lives only here; every exit path nulls it.
  const [revealed, setRevealed] = useState<string | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [revealError, setRevealError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  function clearReveal() {
    setRevealed(null);
    setRevealError(null);
  }

  async function reveal() {
    if (!onReveal) return;
    setRevealing(true);
    setRevealError(null);
    try {
      const v = await onReveal();
      if (alive.current) setRevealed(v);
    } catch (e) {
      if (alive.current) setRevealError(errorMessage(e));
    } finally {
      if (alive.current) setRevealing(false);
    }
  }

  // `stored` flipping (mount, or a parent record reloading with a secret it
  // didn't have before) re-enters stored/"keep it" mode.
  useEffect(() => {
    setEditing(!stored);
    setRemoved(false);
    setShown(false);
    setRevealed(null);
    setRevealError(null);
  }, [stored]);

  // An outside reset to the stored sentinel (Discard, or a save that reloaded
  // the record) returns the control to "Stored"; otherwise a stale
  // `editing`/`removed` would let a later type-then-clear send '' and wipe it.
  useEffect(() => {
    if (value === emitted.current) return;
    emitted.current = value;
    if (stored && (value === UNCHANGED || value === undefined)) {
      setEditing(false);
      setRemoved(false);
      setShown(false);
      setRevealed(null);
      setRevealError(null);
    }
  }, [value, stored]);

  // Proactively emit the sentinel whenever we're showing "Stored" and
  // untouched, instead of relying on the caller to have seeded it.
  useEffect(() => {
    if (stored && !editing && value !== UNCHANGED) onChange(UNCHANGED);
  }, [stored, editing, value, onChange]);

  const revealedValue =
    revealed !== null ? (
      <code
        className="max-w-[28ch] truncate rounded-sm bg-subtle px-2 py-1 font-mono text-xs select-all"
        title={revealed}
        aria-label={`${label} value`}
      >
        {revealed}
      </code>
    ) : null;
  const revealIcon =
    revealing ? (
      <Loader2 className="size-4 animate-spin" aria-hidden />
    ) : revealed !== null ? (
      <EyeOff className="size-4" aria-hidden />
    ) : revealError ? (
      <CircleAlert className="size-4 text-failed" aria-hidden />
    ) : (
      <Eye className="size-4" aria-hidden />
    );
  const revealButton = revealDisabledReason ? (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          <Button type="button" variant="ghost" size="icon" className="size-8 text-ink-muted hover:text-ink" aria-label={`Reveal ${label}`} disabled>
            <Eye className="size-4" aria-hidden />
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{revealDisabledReason}</TooltipContent>
    </Tooltip>
  ) : (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-8 text-ink-muted hover:text-ink"
          aria-label={revealed !== null ? `Hide ${label}` : `Reveal ${label}`}
          aria-busy={revealing || undefined}
          disabled={revealing}
          onClick={() => (revealed !== null ? clearReveal() : void reveal())}
        >
          {revealIcon}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        {revealed !== null ? 'Hide value' : revealError ? revealError : 'Show stored value (logged in the audit trail)'}
      </TooltipContent>
    </Tooltip>
  );

  if (disabled) {
    return (
      <div className="flex h-9 items-center gap-2">
        {stored && onReveal && revealed !== null ? (
          revealedValue
        ) : (
          <span className="inline-flex h-6 items-center gap-1 rounded-sm bg-subtle px-2 text-xs font-semibold text-ink-muted">
            <Lock className="size-3.5" aria-hidden />
            {stored ? 'Stored' : 'Not set'}
          </span>
        )}
        {stored && onReveal && revealButton}
      </div>
    );
  }

  if (stored && !editing) {
    return (
      <div className="flex h-9 items-center gap-2">
        {revealed !== null ? (
          revealedValue
        ) : (
          <span className="inline-flex h-6 items-center gap-1 rounded-sm bg-subtle px-2 text-xs font-semibold">
            <Lock className="size-3.5 text-ink-muted" aria-hidden />
            Stored
          </span>
        )}
        {onReveal && revealButton}
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label={`Replace ${label}`}
          onClick={() => {
            clearReveal();
            setEditing(true);
            setRemoved(false);
            onChange(UNCHANGED);
          }}
        >
          Replace
        </Button>
        {removeDisabledReason ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="inline-flex">
                <Button type="button" variant="ghost" size="sm" aria-label={`Remove ${label}`} disabled>
                  Remove
                </Button>
              </span>
            </TooltipTrigger>
            <TooltipContent>{removeDisabledReason}</TooltipContent>
          </Tooltip>
        ) : (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            aria-label={`Remove ${label}`}
            onClick={() => {
              // The server clears the stored secret on an explicit "" (unlike
              // UNCHANGED, which keeps it) — never sent unless the caller asks.
              clearReveal();
              setEditing(true);
              setRemoved(true);
              onChange('');
            }}
          >
            Remove
          </Button>
        )}
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <div className="relative flex-1">
        <Input
          id={id}
          type={shown ? 'text' : 'password'}
          aria-label={label}
          aria-describedby={`${id}-hint`}
          autoComplete="new-password"
          className="pr-9 font-mono text-xs"
          placeholder={placeholder}
          value={value === UNCHANGED ? '' : (value ?? '')}
          onChange={(e) => {
            const v = e.target.value;
            if (v !== '') {
              onChange(v);
              return;
            }
            // Cleared back to empty: Remove's "" sticks; a plain Replace
            // that's cleared reverts to keeping the stored value.
            onChange(removed ? '' : stored ? UNCHANGED : undefined);
          }}
        />
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="absolute right-0.5 top-1/2 size-8 -translate-y-1/2 text-ink-muted hover:text-ink"
              aria-label={`${shown ? 'Hide' : 'Show'} ${label}`}
              aria-pressed={shown}
              aria-controls={id}
              onClick={() => setShown((s) => !s)}
            >
              {shown ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
            </Button>
          </TooltipTrigger>
          <TooltipContent>{shown ? 'Hide value' : 'Show value'}</TooltipContent>
        </Tooltip>
      </div>
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
            setRemoved(false);
            setShown(false);
            onChange(UNCHANGED);
          }}
        >
          Keep stored
        </Button>
      )}
    </div>
  );
}
