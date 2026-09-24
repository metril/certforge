import { useMemo, useState, type Dispatch } from 'react';
import { DndContext, KeyboardSensor, PointerSensor, useDraggable, useDroppable, useSensor, useSensors } from '@dnd-kit/core';
import { CircleAlert, Crown, X } from 'lucide-react';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { Textarea } from '@/components/ui/textarea';
import { classifyName, groupByZone, MAX_NAMES, splitNames, type ParsedName } from '@/lib/names';
import { cn } from '@/lib/utils';
import type { WizardAction, WizardState } from './state';

const CN_SLOT = 'cn-slot';

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
      <span className="text-sm font-semibold">Common name</span>
      <HelpTip id="cert.cn" />
      <span data-testid="cn" className="font-mono text-xs">
        {value ?? '–'}
      </span>
    </div>
  );
}

function Tag({ children }: { children: string }) {
  return <span className="rounded-sm bg-subtle px-1 font-sans text-xs leading-4 text-ink-muted">{children}</span>;
}

function NameChip({ name, isCn, dispatch }: { name: ParsedName; isCn: boolean; dispatch: Dispatch<WizardAction> }) {
  const bad = name.kind === 'invalid';
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, transform, isDragging } = useDraggable({
    id: name.value,
    disabled: bad || isCn,
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
        {...attributes}
        aria-roledescription="draggable name"
        className={cn(!bad && !isCn && 'cursor-grab')}
      >
        {name.value}
      </span>
      {name.kind === 'wildcard' && <Tag>DNS only</Tag>}
      {name.kind === 'ip' && <Tag>IP</Tag>}
      {bad && (
        <>
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          <span className="sr-only">{name.error}</span>
          <HelpTip text={name.error} />
        </>
      )}
      {!isCn && !bad && (
        <button
          type="button"
          aria-label={`Make ${name.value} the common name`}
          onClick={() => dispatch({ type: 'setCn', name: name.value })}
          className="rounded-sm p-1 text-ink-muted hover:text-ink"
        >
          <Crown className="size-3.5" aria-hidden />
        </button>
      )}
      <button
        type="button"
        aria-label={`Remove ${name.value}`}
        onClick={() => dispatch({ type: 'removeName', name: name.value })}
        className="rounded-sm p-1 text-ink-muted hover:text-ink"
      >
        <X className="size-3.5" aria-hidden />
      </button>
    </span>
  );
}

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
            add(`${draft} ${e.clipboardData.getData('text/plain')}`);
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
