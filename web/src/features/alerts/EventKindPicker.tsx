import { Check } from 'lucide-react';
import type { EventKind } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { HelpTip } from '@/components/HelpTip';
import { CHANNEL_KINDS, KIND_GROUPS, KIND_SHORT } from '@/lib/events';
import { cn } from '@/lib/utils';

// Every group but Test (Deviations, UI conventions: Test is an event-log
// filter only, never a channel filter).
const GROUPS = KIND_GROUPS.filter((g) => g.label !== 'Test');

/**
 * A channel's event filter (Task 3): a lone "All events" chip, filled when
 * the selection is empty and clearing it on click, above one ChipSet per
 * KIND_GROUPS group (short labels — the group name already gives context).
 * Selecting any kind unfills "All events"; the emitted array is always in
 * EventKind enum order regardless of click order across groups.
 */
export function EventKindPicker({ value, onChange }: { value: EventKind[]; onChange: (v: EventKind[]) => void }) {
  const allSelected = value.length === 0;
  return (
    <div className="grid gap-3">
      <div className="flex items-center gap-1.5">
        <span className="text-sm font-semibold">Events</span>
        <HelpTip id="channel.events" />
      </div>
      <button
        type="button"
        aria-pressed={allSelected}
        onClick={() => onChange([])}
        className={cn(
          'inline-flex h-7 w-fit items-center gap-1 rounded-sm border px-2.5 text-sm transition-colors',
          allSelected ? 'border-primary bg-primary text-on-primary' : 'border-border bg-panel text-ink hover:bg-subtle',
        )}
      >
        {allSelected && <Check className="size-3.5" aria-hidden />}
        All events
      </button>
      {GROUPS.map((g) => (
        <div key={g.label} className="grid gap-1.5">
          <span className="text-xs font-medium text-ink-muted">{g.label}</span>
          <ChipSet<EventKind>
            aria-label={g.label}
            value={value.filter((k) => g.kinds.includes(k))}
            onChange={(groupSelected) => {
              const rest = value.filter((k) => !g.kinds.includes(k));
              const merged = new Set([...rest, ...groupSelected]);
              onChange(CHANNEL_KINDS.filter((k) => merged.has(k)));
            }}
            options={g.kinds.map((k) => ({ value: k, label: KIND_SHORT[k] }))}
          />
        </div>
      ))}
    </div>
  );
}
