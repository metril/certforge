import { useRef, useState } from 'react';
import { closestCenter, DndContext, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { ChevronDown, ChevronUp, CircleAlert, GripVertical, Plus, X } from 'lucide-react';
import type { DnsCredential, VerificationMethod, VerificationRule } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { ListInput } from '@/components/ListInput';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { matchError } from '@/lib/coverage';
import { LATER } from '@/lib/nav';
import { cn } from '@/lib/utils';

let seq = 0;
const newKey = () => `rule-${++seq}`;

type RowProps = {
  id: string;
  index: number;
  rule: VerificationRule;
  method: VerificationMethod;
  credentials: DnsCredential[];
  onUpdate: (patch: Partial<VerificationRule>) => void;
  onRemove: () => void;
  onMove: (delta: -1 | 1) => void;
  canMoveUp: boolean;
  canMoveDown: boolean;
  onAddCredential?: () => void;
};

function RuleRow({ id, index, rule, method, credentials, onUpdate, onRemove, onMove, canMoveUp, canMoveDown, onAddCredential }: RowProps) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id });
  const [advanced, setAdvanced] = useState(false);
  const n = index + 1;
  // Fix round 1 (review, item 2): only nag once the operator has typed
  // something — an empty freshly-added row still blocks Next (via
  // verificationReady) without an immediate "Required." error.
  const matchErr = rule.match.trim() ? matchError(rule.match) : null;
  const errorId = `${id}-match-error`;
  return (
    <li
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={cn('grid gap-2 border-b border-border py-2 last:border-b-0 max-md:rounded-md max-md:border max-md:p-2', isDragging && 'bg-subtle')}
    >
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" aria-label={`Reorder rule ${n}`} {...attributes} {...listeners} className="cursor-grab rounded-sm p-1 text-ink-muted hover:text-ink">
          <GripVertical className="size-4" aria-hidden />
        </button>
        <div className="flex flex-col">
          <Button type="button" variant="ghost" size="icon-sm" aria-label={`Move rule ${n} up`} disabled={!canMoveUp} onClick={() => onMove(-1)}>
            <ChevronUp className="size-4" aria-hidden />
          </Button>
          <Button type="button" variant="ghost" size="icon-sm" aria-label={`Move rule ${n} down`} disabled={!canMoveDown} onClick={() => onMove(1)}>
            <ChevronDown className="size-4" aria-hidden />
          </Button>
        </div>
        <span className="w-4 text-xs tabular-nums text-ink-muted">{n}</span>
        <Input
          aria-label={`Rule ${n} match`}
          aria-describedby={matchErr ? errorId : undefined}
          aria-invalid={!!matchErr}
          className="w-full font-mono text-xs sm:w-56"
          value={rule.match}
          placeholder="*.example.com"
          onChange={(e) => onUpdate({ match: e.target.value })}
        />
        {method === 'dns-01' && (
          <div className="w-full sm:w-64">
            <Combobox
              aria-label={`Rule ${n} credential`}
              value={rule.dnsCredentialId}
              onChange={(v) => onUpdate({ dnsCredentialId: v })}
              options={credentials.map((c) => ({ value: c.id, label: c.name, hint: c.providerCode }))}
              placeholder="Choose credential"
              emptyText="No credentials yet"
              footer={
                onAddCredential && (
                  <Button type="button" variant="ghost" size="sm" className="w-full justify-start" onClick={onAddCredential}>
                    <Plus className="size-4" aria-hidden />
                    Add credential
                  </Button>
                )
              }
            />
          </div>
        )}
        <Button type="button" variant="ghost" size="sm" aria-expanded={advanced} onClick={() => setAdvanced((a) => !a)}>
          Advanced
        </Button>
        <Button type="button" variant="ghost" size="icon" aria-label={`Remove rule ${n}`} onClick={onRemove}>
          <X className="size-4" aria-hidden />
        </Button>
      </div>
      {matchErr && (
        <p id={errorId} role="alert" className="flex items-center gap-1 pl-11 text-xs">
          <CircleAlert className="size-3.5 shrink-0 text-failed" aria-hidden />
          {matchErr}
        </p>
      )}
      {advanced && (
        <div className="grid gap-3 md:pl-11 lg:grid-cols-3">
          <Field id={`${id}-prop`} label="Propagation" help="rules.propagation" optional>
            <Input
              id={`${id}-prop`}
              type="number"
              min={0}
              placeholder="120"
              value={rule.propagationSeconds ?? ''}
              onChange={(e) => onUpdate({ propagationSeconds: e.target.value === '' ? undefined : Number(e.target.value) })}
            />
          </Field>
          <Field id={`${id}-res`} label="Resolvers" help="defaults.resolvers" optional>
            <ListInput id={`${id}-res`} value={rule.resolvers ?? []} onChange={(v) => onUpdate({ resolvers: v.length ? v : undefined })} placeholder="1.1.1.1:53" />
          </Field>
          {method === 'dns-01' && (
            <Field id={`${id}-cname`} label="CNAME alias zone" help="rules.cnameAlias" optional>
              <Input id={`${id}-cname`} className="font-mono text-xs" placeholder="acme.example.net" value={rule.cnameAliasZone ?? ''} onChange={(e) => onUpdate({ cnameAliasZone: e.target.value || undefined })} />
            </Field>
          )}
        </div>
      )}
    </li>
  );
}

type Props = {
  rules: VerificationRule[];
  onChange: (rules: VerificationRule[]) => void;
  method: VerificationMethod;
  onMethodChange: (m: VerificationMethod) => void;
  credentials: DnsCredential[];
  onAddCredential?: (ruleIndex: number) => void;
};

export function VerificationRulesEditor({ rules, onChange, method, onMethodChange, credentials, onAddCredential }: Props) {
  const keys = useRef<string[]>([]);
  while (keys.current.length < rules.length) keys.current.push(newKey());
  keys.current.length = rules.length;
  const sensors = useSensors(useSensor(PointerSensor), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));
  const update = (i: number, patch: Partial<VerificationRule>) => onChange(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const move = (i: number, delta: -1 | 1) => {
    const to = i + delta;
    if (to < 0 || to >= rules.length) return;
    keys.current = arrayMove(keys.current, i, to);
    onChange(arrayMove(rules, i, to));
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold">Method</span>
        <HelpTip id="rules.method" />
        <SegmentedControl<VerificationMethod | 'http-01'>
          aria-label="Verification method"
          value={method}
          onChange={(m) => m !== 'http-01' && onMethodChange(m)}
          options={[
            { value: 'dns-01', label: 'DNS-01' },
            { value: 'manual-dns', label: 'Manual DNS' },
            { value: 'http-01', label: 'HTTP-01', disabled: true, hint: LATER },
          ]}
        />
      </div>
      {/* Fix round 1 (review, item 4): column headers, hidden below md
          (the row becomes a stacked card there), wiring the previously
          unused rules.match / rules.credential help entries. */}
      <div className="hidden items-center gap-2 px-1 text-xs font-medium text-ink-muted md:flex">
        <span className="w-6" aria-hidden />
        <span className="w-8" aria-hidden />
        <span className="w-4" aria-hidden />
        <span className="flex w-56 items-center gap-1">
          Match <HelpTip id="rules.match" />
        </span>
        {method === 'dns-01' && (
          <span className="flex w-64 items-center gap-1">
            Credential <HelpTip id="rules.credential" />
          </span>
        )}
      </div>
      <DndContext
        sensors={sensors}
        collisionDetection={closestCenter}
        onDragEnd={({ active, over }) => {
          if (!over || active.id === over.id) return;
          const from = keys.current.indexOf(String(active.id));
          const to = keys.current.indexOf(String(over.id));
          keys.current = arrayMove(keys.current, from, to);
          onChange(arrayMove(rules, from, to));
        }}
      >
        <SortableContext items={keys.current} strategy={verticalListSortingStrategy}>
          <ol aria-label="Verification rules" className="grid gap-2 md:gap-0">
            {rules.map((r, i) => (
              <RuleRow
                key={keys.current[i]}
                id={keys.current[i]!}
                index={i}
                rule={r}
                method={method}
                credentials={credentials}
                onUpdate={(p) => update(i, p)}
                onRemove={() => {
                  keys.current.splice(i, 1);
                  onChange(rules.filter((_, j) => j !== i));
                }}
                onMove={(delta) => move(i, delta)}
                canMoveUp={i > 0}
                canMoveDown={i < rules.length - 1}
                onAddCredential={onAddCredential && (() => onAddCredential(i))}
              />
            ))}
          </ol>
        </SortableContext>
      </DndContext>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-fit"
        onClick={() => onChange([...rules, { match: '', method, via: 'server' as const }])}
      >
        <Plus className="size-4" aria-hidden />
        Add rule
      </Button>
    </div>
  );
}
