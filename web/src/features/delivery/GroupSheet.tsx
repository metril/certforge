import { FormSection } from '@/components/FormSection';
import { useState } from 'react';
import { ArrowDown, ArrowUp, X } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { useSaveActionGroup } from '@/api/queries/delivery';
import type { Action, ActionGroup } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { IconButton } from '@/components/IconButton';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose, useSheetGuard, SheetBody } from '@/components/ui/sheet';
import { RUNS_ON_META } from '@/lib/targets';
import { useDirty } from '@/lib/useDirty';

const MAX_ACTIONS = 32;

type Props = { orgId: string; group?: ActionGroup; actions: Action[]; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function GroupSheet({ orgId, group, actions, readOnly, onOpenChange }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const save = useSaveActionGroup(orgId);
  const [name, setName] = useState(group?.name ?? '');
  const [ids, setIds] = useState<string[]>(group?.actionIds ?? []);
  const [nameError, setNameError] = useState<string | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const dirty = useDirty({ name, ids });
  const byId = new Map(actions.map((a) => [a.id, a]));
  const title = group ? (readOnly ? group.name : `Edit ${group.name}`) : 'New action group';

  const move = (i: number, d: -1 | 1) =>
    setIds((cur) => {
      const next = [...cur];
      [next[i], next[i + d]] = [next[i + d]!, next[i]!];
      return next;
    });

  const submit = async () => {
    setFormError(null);
    const trimmed = name.trim();
    const nameOk = trimmed !== '' && trimmed.length <= 100;
    setNameError(trimmed === '' ? 'Enter a name.' : nameOk ? null : 'Use 1 to 100 characters.');
    const listOk = ids.length <= MAX_ACTIONS;
    setListError(listOk ? null : `Use at most ${MAX_ACTIONS} actions.`);
    if (!nameOk || !listOk) return;
    try {
      await save.mutateAsync({ id: group?.id, body: { name: trimmed, actionIds: ids } });
      guard.close();
    } catch (e) {
      const msg = errorMessage(e);
      if (e instanceof ApiError && e.status === 409 && /named/i.test(msg)) setNameError(msg);
      else setFormError(msg);
    }
  };

  return (
    <Sheet guard={guard} open form={!readOnly} dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" size="xl">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription className="sr-only">An ordered list of actions a grant can run as one step</SheetDescription>
        </SheetHeader>
        <SheetBody>
          <div className="grid gap-4">
            <FormSection title="General">
              <Field id="group-name" label="Name" error={nameError}>
                <Input
                  id="group-name"
                  value={name}
                  placeholder="restart and verify"
                  autoComplete="off"
                  disabled={readOnly}
                  onChange={(e) => {
                    setName(e.target.value);
                    setNameError(null);
                  }}
                />
              </Field>
            </FormSection>
            <FormSection title="Actions" help="action.group" summary={`${ids.length} of ${MAX_ACTIONS}`}>
              {ids.length === 0 ? (
                <p className="text-sm text-ink-muted">No actions yet. Add them in the order they should run.</p>
              ) : (
                <ol aria-label="Actions in order" className="grid gap-1">
                  {ids.map((id, i) => {
                    const a = byId.get(id);
                    return (
                      <li key={`${i}-${id}`} className="flex items-center gap-1 rounded-md border border-border bg-panel px-2 py-1">
                        <span className="w-6 text-xs text-ink-muted">{i + 1}</span>
                        <span className="min-w-0 flex-1 truncate text-sm">{a?.name ?? 'Unknown action'}</span>
                        {a && <span className="text-xs text-ink-muted">{RUNS_ON_META[a.runsOn].label}</span>}
                        {!readOnly && (
                          <>
                            <IconButton type="button" variant="ghost" size="icon-sm" className="size-7" label={`Move ${a?.name ?? 'action'} up`} disabled={i === 0} onClick={() => move(i, -1)}>
                              <ArrowUp className="size-3.5" aria-hidden />
                            </IconButton>
                            <IconButton
                              type="button"
                              variant="ghost"
                              size="icon-sm"
                              className="size-7"
                              label={`Move ${a?.name ?? 'action'} down`}
                              disabled={i === ids.length - 1}
                              onClick={() => move(i, 1)}
                            >
                              <ArrowDown className="size-3.5" aria-hidden />
                            </IconButton>
                            <IconButton
                              type="button"
                              variant="ghost"
                              size="icon-sm"
                              className="size-7"
                              label={`Remove ${a?.name ?? 'action'}`}
                              onClick={() => setIds((cur) => cur.filter((_, j) => j !== i))}
                            >
                              <X className="size-3.5" aria-hidden />
                            </IconButton>
                          </>
                        )}
                      </li>
                    );
                  })}
                </ol>
              )}
              {listError && <p className="text-sm text-failed">{listError}</p>}
              {!readOnly && (
                <Combobox
                  id="group-add"
                  aria-label="Add action"
                  value={undefined}
                  onChange={(v) => v && setIds((cur) => [...cur, v])}
                  options={actions.map((a) => ({ value: a.id, label: a.name, hint: RUNS_ON_META[a.runsOn].label }))}
                  placeholder="Add an action"
                  emptyText="No action matches."
                  disabled={ids.length >= MAX_ACTIONS}
                />
              )}
            </FormSection>
            {formError && (
              <p role="alert" className="text-sm">
                {formError}
              </p>
            )}
          </div>
        </SheetBody>
        <SheetFooter>
          {readOnly ? (
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          ) : (
            <>
              <SheetClose asChild>
                <Button variant="outline">Cancel</Button>
              </SheetClose>
              <Button disabled={save.isPending} onClick={() => void submit()}>
                Save
              </Button>
            </>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
