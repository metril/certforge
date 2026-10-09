import { memo, useMemo, useState, type Dispatch } from 'react';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
  type Announcements,
} from '@dnd-kit/core';
import { CircleAlert, Crown, Globe, ShieldAlert, X } from 'lucide-react';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { IconButton } from '@/components/IconButton';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Textarea } from '@/components/ui/textarea';
import { help, type HelpKey } from '@/lib/help';
import { classifyName, groupByZone, MAX_NAMES, splitNames, type ParsedName } from '@/lib/names';
import { cn } from '@/lib/utils';
import type { WizardAction, WizardState } from './state';

const CN_SLOT = 'cn-slot';
const CN_SLOT_LABEL = 'Common name';

// Fix round 1 (review, Take-now #3): dnd-kit's default screen-reader
// announcements name a droppable by its raw `id` ("cn-slot"); name it the
// way it reads on screen instead.
const announcements: Announcements = {
  onDragStart: ({ active }) => `Picked up ${active.id}.`,
  onDragOver: ({ active, over }) =>
    over ? `${active.id} is over ${over.id === CN_SLOT ? CN_SLOT_LABEL : over.id}.` : `${active.id} is no longer over a droppable area.`,
  onDragEnd: ({ active, over }) =>
    over ? `${active.id} was dropped over ${over.id === CN_SLOT ? CN_SLOT_LABEL : over.id}.` : `${active.id} was dropped.`,
  onDragCancel: ({ active }) => `Dragging ${active.id} was cancelled.`,
};

function CnSlot({ value }: { value: string | null }) {
  const { setNodeRef, isOver } = useDroppable({ id: CN_SLOT });
  return (
    <div
      ref={setNodeRef}
      className={cn(
        'flex min-h-10 items-center gap-2 rounded-md border border-dashed px-3',
        isOver ? 'border-primary bg-primary/8' : 'border-border',
      )}
    >
      <span className="text-sm font-semibold">{CN_SLOT_LABEL}</span>
      <HelpTip id="cert.cn" />
      <span data-testid="cn" className="font-mono text-xs">
        {value ?? '–'}
      </span>
    </div>
  );
}

// Fix round 1 (review, Important #2): a plan-mandated chip marker is an
// icon plus a word plus a tooltip when it needs explaining, not a bare word
// — the wildcard and IP markers below now carry both, sourced from
// `lib/help.ts` like every other tooltip in the app.
function MarkerTag({ icon: Icon, label, helpKey }: { icon: typeof Globe; label: string; helpKey: HelpKey }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="inline-flex items-center gap-0.5 rounded-sm bg-subtle px-1 font-sans text-xs leading-4 text-ink-muted"
        >
          <Icon className="size-3" aria-hidden />
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
        {help[helpKey].text}
      </TooltipContent>
    </Tooltip>
  );
}

// Fix round 1 (review, Take-now #5): every NameChip subscribes to dnd-kit's
// internal drag context (via useDraggable), so memoizing it doesn't block
// that; what it does stop is every chip re-rendering whenever NamesStep
// itself re-renders for an unrelated reason (typing in the paste box, a
// sibling's own state) despite this chip's own props (name, isCn, dispatch)
// staying referentially equal.
const NameChip = memo(function NameChip({
  name,
  isCn,
  dispatch,
}: {
  name: ParsedName;
  isCn: boolean;
  dispatch: Dispatch<WizardAction>;
}) {
  const bad = name.kind === 'invalid';
  const disabled = bad || isCn;
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, transform, isDragging } = useDraggable({
    id: name.value,
    disabled,
  });
  return (
    <span
      ref={setNodeRef}
      style={transform ? { transform: `translate(${transform.x}px, ${transform.y}px)` } : undefined}
      className={cn(
        'inline-flex h-7 items-center gap-1 rounded-sm border bg-panel pl-2 pr-0.5 font-mono text-xs',
        bad ? 'border-failed' : isCn ? 'border-primary' : 'border-border',
        isDragging && 'z-10 opacity-70',
      )}
    >
      <span
        ref={setActivatorNodeRef}
        {...listeners}
        {...(disabled ? undefined : attributes)}
        aria-roledescription={disabled ? undefined : 'draggable name'}
        className={cn(!disabled && 'cursor-grab')}
      >
        {name.value}
      </span>
      {name.kind === 'wildcard' && <MarkerTag icon={Globe} label="DNS only" helpKey="cert.wildcardMarker" />}
      {name.kind === 'ip' && <MarkerTag icon={ShieldAlert} label="IP" helpKey="cert.ipMarker" />}
      {bad && (
        <>
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          <span className="sr-only">{name.error}</span>
          <HelpTip text={name.error} />
        </>
      )}
      {!isCn && !bad && (
        <IconButton
          type="button"
          variant="ghost"
          size="icon-xs"
          label={`Make ${name.value} the common name`}
          onClick={() => dispatch({ type: 'setCn', name: name.value })}
          className="size-auto rounded-sm p-1 text-ink-muted hover:bg-transparent hover:text-ink"
        >
          <Crown className="size-3.5" aria-hidden />
        </IconButton>
      )}
      <IconButton
        type="button"
        variant="ghost"
        size="icon-xs"
        label={`Remove ${name.value}`}
        onClick={() => dispatch({ type: 'removeName', name: name.value })}
        className="size-auto rounded-sm p-1 text-ink-muted hover:bg-transparent hover:text-ink"
      >
        <X className="size-3.5" aria-hidden />
      </IconButton>
    </span>
  );
});

export function NamesStep({ state, dispatch }: { state: WizardState; dispatch: Dispatch<WizardAction> }) {
  const [draft, setDraft] = useState('');
  const parsed = useMemo(() => state.names.map(classifyName), [state.names]);
  const groups = useMemo(() => groupByZone(parsed), [parsed]);
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 4 } }), useSensor(KeyboardSensor));
  const over = state.names.length > MAX_NAMES;

  const add = (text: string) => {
    const names = splitNames(text);
    if (names.length) dispatch({ type: 'addNames', names });
    setDraft('');
  };

  return (
    <div className="grid gap-5">
      <Field id="names-input" label="Names" help="cert.names">
        <Textarea
          id="names-input"
          rows={3}
          className="font-mono text-xs"
          placeholder="example.com, *.example.com"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onPaste={(e) => {
            e.preventDefault();
            const { selectionStart: a, selectionEnd: b } = e.currentTarget;
            add(`${draft.slice(0, a)} ${e.clipboardData.getData('text/plain')} ${draft.slice(b)}`);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              add(draft);
            }
          }}
          onBlur={() => draft.trim() && add(draft)}
        />
      </Field>
      <DndContext
        sensors={sensors}
        accessibility={{ announcements }}
        onDragEnd={(e) => {
          if (e.over?.id === CN_SLOT && typeof e.active.id === 'string') dispatch({ type: 'setCn', name: e.active.id });
        }}
      >
        <CnSlot value={state.cn} />
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span>{state.names.length === 1 ? '1 name' : `${state.names.length} names`}</span>
          {over && (
            <span role="alert" className="flex items-center gap-1">
              <CircleAlert className="size-4 text-failed" aria-hidden />
              {MAX_NAMES} names max per certificate
            </span>
          )}
        </div>
        {groups.map((g) => (
          <section key={g.zone} aria-label={g.zone} className="grid gap-1.5">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <span className={g.kind === 'zone' ? 'font-mono text-xs' : undefined}>{g.zone}</span>
              <span className="text-xs font-normal text-ink-muted">{g.names.length}</span>
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {g.names.map((n) => (
                <NameChip key={n.value} name={n} isCn={n.value === state.cn} dispatch={dispatch} />
              ))}
            </div>
          </section>
        ))}
      </DndContext>
    </div>
  );
}
