import { useDirty } from '@/lib/useDirty';
import { useState } from 'react';
import { ApiError, errorMessage } from '@/api/errors';
import { useSaveHook } from '@/api/queries/delivery';
import type { Hook, HookKind, HookPhase } from '@/api/types';
import { Field } from '@/components/Field';
import { FormSection } from '@/components/FormSection';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose, useSheetGuard } from '@/components/ui/sheet';
import { ArgvField, argvErrors } from '@/forms/widgets/ArgvField';
import { PHASE_LABEL } from '@/lib/clientStatus';

const RESTART_TARGET = /^(docker|systemd):[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/;

type Props = { orgId: string; hook?: Hook; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function HookSheet({ orgId, hook, readOnly, onOpenChange }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const save = useSaveHook(orgId);
  const [name, setName] = useState(hook?.name ?? '');
  const [phase, setPhase] = useState<HookPhase>(hook?.phase ?? 'post_deploy');
  const [kind, setKind] = useState<HookKind>(hook?.kind ?? 'exec');
  const [target, setTarget] = useState(hook?.target ?? 'docker:');
  const [argv, setArgv] = useState<string[]>(hook?.argv ?? ['']);
  const [timeout, setTimeoutText] = useState(String(hook?.timeoutSeconds ?? 60));
  const [show, setShow] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const dirty = useDirty({ name, phase, kind, target, argv, timeout });
  const errs = kind === 'exec' ? argvErrors(argv) : [];
  const targetError = kind === 'restart' && !RESTART_TARGET.test(target) ? 'Use docker:<container> or systemd:<unit>.' : null;
  const seconds = Number(timeout);
  const timeoutError = Number.isInteger(seconds) && seconds >= 1 && seconds <= 3600 ? null : 'Use 1 to 3600 seconds.';
  const title = hook ? (readOnly ? hook.name : `Edit ${hook.name}`) : 'New hook';

  const submit = async () => {
    setShow(true);
    setFormError(null);
    const trimmedName = name.trim();
    const nameOk = trimmedName !== '' && trimmedName.length <= 100;
    setNameError(trimmedName === '' ? 'Enter a name.' : nameOk ? null : 'Use 1 to 100 characters.');
    if (!nameOk || errs.some(Boolean) || targetError || timeoutError) return;
    try {
      await save.mutateAsync({ id: hook?.id, body: kind === 'restart' ? { name: trimmedName, phase, kind, target, argv: [], timeoutSeconds: seconds } : { name: trimmedName, phase, kind, argv, timeoutSeconds: seconds } });
      guard.close();
    } catch (e) {
      const msg = errorMessage(e);
      // Only a name conflict ("A hook named ... exists in this org" — the
      // server's own wording) belongs under Name; any other 409 (or a
      // 422/5xx) reads better as a page-level alert than silently attached
      // to the wrong field (mirroring Task 7/8's Target/LayoutSheet).
      if (e instanceof ApiError && e.status === 409 && /^A hook named/i.test(msg)) setNameError(msg);
      else setFormError(msg);
    }
  };

  return (
    <Sheet guard={guard} open form={!readOnly} dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription className="sr-only">A command agents run around a deploy</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <Field id="hook-name" label="Name" error={nameError}>
            <Input
              id="hook-name"
              value={name}
              placeholder="reload nginx"
              autoComplete="off"
              disabled={readOnly}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
            />
          </Field>
          <Field id="hook-phase" label="Phase" help="hook.phase">
            <SegmentedControl<HookPhase>
              id="hook-phase"
              aria-label="Phase"
              value={phase}
              onChange={setPhase}
              options={(['pre_deploy', 'post_deploy'] as const).map((p) => ({ value: p, label: PHASE_LABEL[p], disabled: readOnly }))}
            />
          </Field>
          <Field id="hook-kind" label="Kind" help="hook.kind">
            <SegmentedControl<HookKind>
              id="hook-kind"
              aria-label="Kind"
              value={kind}
              onChange={setKind}
              options={[
                { value: 'exec', label: 'Exec', disabled: readOnly },
                { value: 'restart', label: 'Restart', disabled: readOnly },
              ]}
            />
          </Field>
          {kind === 'exec' ? (
            <div className="grid gap-1.5">
              <span className="flex items-center gap-1.5 text-sm font-medium">
                Command <HelpTip id="hook.argv" />
              </span>
              <ArgvField id="hook-argv" value={argv} onChange={setArgv} errors={show ? errs : []} disabled={readOnly} />
            </div>
          ) : (
            <Field id="hook-target" label="Target" help="hook.target" error={show ? targetError : null}>
              <Input
                id="hook-target"
                value={target}
                placeholder="docker:nginx or systemd:nginx.service"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                disabled={readOnly}
                onChange={(e) => setTarget(e.target.value)}
              />
            </Field>
          )}
          <FormSection title="Limits">
          <Field id="hook-timeout" label="Timeout" help="hook.timeout" error={show ? timeoutError : null}>
            <div className="flex items-center gap-2">
              <Input
                id="hook-timeout"
                type="number"
                inputMode="numeric"
                min={1}
                max={3600}
                className="w-28"
                value={timeout}
                disabled={readOnly}
                onChange={(e) => setTimeoutText(e.target.value)}
              />
              <span className="text-sm text-ink-muted">seconds</span>
            </div>
          </Field>
          </FormSection>
          {formError && (
            <p role="alert" className="text-sm">
              {formError}
            </p>
          )}
        </div>
        <SheetFooter className="flex-row justify-end gap-2">
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
