import { useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { ErrorSchema, RJSFSchema } from "@rjsf/utils";
import { toast } from "sonner";
import { ApiError, errorMessage } from "@/api/errors";
import {
  createAction,
  invalidateActions,
  updateAction,
} from "@/api/queries/delivery";
import type {
  Action,
  ActionInput,
  ActionKind,
  ActionPhase,
  ActionSchemaEntry,
} from "@/api/types";
import { Combobox } from "@/components/Combobox";
import { Field } from "@/components/Field";
import { FormSection } from "@/components/FormSection";
import { HelpTip } from "@/components/HelpTip";
import { RunsOnChip } from "@/components/RunsOnChip";
import { SegmentedControl } from "@/components/SegmentedControl";
import { SwitchField } from "@/components/SwitchField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetClose,
  useSheetGuard,
  SheetBody,
} from "@/components/ui/sheet";
import { ArgvField, argvErrors } from "@/forms/widgets/ArgvField";
import { SchemaForm, type SchemaFormHandle } from "@/forms/SchemaForm";
import { fieldErrorFromMessage } from "@/forms/uiSchema";
import { PHASE_LABEL } from "@/lib/clientStatus";
import {
  stripSecretDefaults,
  settledConfig,
  withStoredSentinels,
} from "@/lib/secretForm";
import { RUNS_ON_META } from "@/lib/targets";
import { useDirty } from "@/lib/useDirty";
import { RestartTargetPicker } from "./RestartTargetPicker";

const RESTART_TARGET = /^(docker|systemd):[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/;
const PF_SERVICE_KEYS =
  "One key per entry: webgui, openvpn:server:<id>, openvpn:client:<id>, ipsec, captiveportal:<zone>, package:<name>.";

type Props = {
  orgId: string;
  action?: Action;
  kinds: ActionSchemaEntry[];
  readOnly: boolean;
  onOpenChange: (open: boolean) => void;
};

export function ActionSheet({
  orgId,
  action,
  kinds,
  readOnly,
  onOpenChange,
}: Props) {
  const guard = useSheetGuard(onOpenChange);
  const qc = useQueryClient();
  const formRef = useRef<SchemaFormHandle>(null);
  const first = kinds[0]!;
  const [name, setName] = useState(action?.name ?? "");
  const [kind, setKind] = useState<string>(action?.kind ?? first.code);
  const [phase, setPhase] = useState<ActionPhase>(
    action?.phase ?? ((first.phaseHint || "post_deploy") as ActionPhase),
  );
  const [config, setConfig] = useState<Record<string, unknown>>(
    (action?.config as Record<string, unknown> | undefined) ?? {},
  );
  const [argv, setArgv] = useState<string[]>(
    (action?.config as { argv?: string[] } | undefined)?.argv ?? [""],
  );
  const [restartTarget, setRestartTarget] = useState(
    (action?.config as { target?: string } | undefined)?.target ?? "docker:",
  );
  const [timeout, setTimeoutText] = useState(
    String(action?.timeoutSeconds ?? 60),
  );
  const [optional, setOptional] = useState(action?.optional ?? false);
  const [show, setShow] = useState(false);
  const [browse, setBrowse] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [extra, setExtra] = useState<ErrorSchema | null>(null);
  const [saving, setSaving] = useState(false);
  const meta = useMemo(
    () => kinds.find((k) => k.code === kind) ?? first,
    [kinds, kind, first],
  );
  const schema = useMemo(
    () => stripSecretDefaults(meta.schema as RJSFSchema),
    [meta],
  );
  const stored = useMemo(
    () => (action && action.kind === kind ? action.secretKeys : []),
    [action, kind],
  );
  const bespoke = kind === "exec" || kind === "restart";
  const formContext = useMemo(
    () => ({ actionForm: { orgId, targetTypes: meta.targetTypes } }),
    [orgId, meta.targetTypes],
  );
  const uiOverrides = useMemo(
    () => ({
      targetId: { "ui:widget": "actionTarget" },
      channelId: { "ui:widget": "channel" },
      ...(kind === "pfsense_restart"
        ? { services: { "ui:description": PF_SERVICE_KEYS } }
        : {}),
    }),
    [kind],
  );
  const argvErrs = kind === "exec" ? argvErrors(argv) : [];
  const targetError =
    kind === "restart" && !RESTART_TARGET.test(restartTarget)
      ? "Use docker:<container> or systemd:<unit>."
      : null;
  const seconds = Number(timeout);
  const timeoutError =
    Number.isInteger(seconds) && seconds >= 1 && seconds <= 3600
      ? null
      : "Use 1 to 3600 seconds.";
  const dirty = useDirty({
    name,
    kind,
    phase,
    optional,
    timeout,
    ...(kind === "exec"
      ? { argv }
      : kind === "restart"
        ? { restartTarget }
        : { config: settledConfig(schema, config, stored) }),
  });
  const title = action
    ? readOnly
      ? action.name
      : `Edit ${action.name}`
    : "New action";

  const changeKind = (v: string | undefined) => {
    if (!v || v === kind) return;
    const m = kinds.find((k) => k.code === v);
    setKind(v);
    setConfig({});
    setExtra(null);
    setFormError(null);
    setShow(false);
    if (m?.runsOn === "agent") setOptional(false);
    if (m?.phaseHint) setPhase(m.phaseHint as ActionPhase);
  };

  const submit = async () => {
    setShow(true);
    setFormError(null);
    const trimmed = name.trim();
    const nameOk = trimmed !== "" && trimmed.length <= 100;
    setNameError(
      trimmed === ""
        ? "Enter a name."
        : nameOk
          ? null
          : "Use 1 to 100 characters.",
    );
    const formOk = bespoke ? true : (formRef.current?.validate() ?? false);
    if (
      !nameOk ||
      !formOk ||
      argvErrs.some(Boolean) ||
      targetError ||
      timeoutError
    )
      return;
    const body: ActionInput = {
      name: trimmed,
      kind: kind as ActionKind,
      phase,
      config:
        kind === "exec"
          ? { argv }
          : kind === "restart"
            ? { target: restartTarget }
            : withStoredSentinels(schema, config, stored),
      timeoutSeconds: seconds,
      optional,
    };
    setSaving(true);
    try {
      if (action) await updateAction(orgId, action.id, body);
      else await createAction(orgId, body);
      toast.success("Action saved");
      await invalidateActions(qc, orgId);
      guard.close();
    } catch (e) {
      const msg = errorMessage(e);
      const field = bespoke ? null : fieldErrorFromMessage(schema, msg);
      if (field) setExtra(field);
      else if (e instanceof ApiError && e.status === 409 && /named/i.test(msg))
        setNameError(msg);
      else setFormError(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet
      guard={guard}
      open
      form={!readOnly}
      dirty={dirty}
      onOpenChange={onOpenChange}
    >
      <SheetContent side="right" size="xl">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription className="sr-only">
            A reusable step a grant runs around a deploy
          </SheetDescription>
        </SheetHeader>
        <SheetBody>
          <div className="grid gap-4">
            <FormSection title="General" columns={2}>
              <Field id="action-name" label="Name" error={nameError}>
                <Input
                  id="action-name"
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
              <Field
                id="action-kind"
                label="Kind"
                help="action.kind"
                className="sm:col-span-2"
              >
                {kinds.length <= 5 ? (
                  <SegmentedControl<string>
                    id="action-kind"
                    aria-label="Kind"
                    value={kind}
                    onChange={changeKind}
                    options={kinds.map((k) => ({
                      value: k.code,
                      label: (
                        <span className="inline-flex items-center gap-1.5">
                          {k.name}
                          <RunsOnChip mode={k.runsOn} />
                        </span>
                      ),
                      disabled: readOnly,
                    }))}
                  />
                ) : (
                  <Combobox
                    id="action-kind"
                    aria-label="Kind"
                    value={kind}
                    onChange={changeKind}
                    options={kinds.map((k) => ({
                      value: k.code,
                      label: k.name,
                      hint: RUNS_ON_META[k.runsOn].label,
                    }))}
                    placeholder="Pick a kind"
                    emptyText="No kind matches."
                    disabled={readOnly}
                  />
                )}
              </Field>
              <Field id="action-phase" label="Phase" help="action.phase">
                <SegmentedControl<ActionPhase>
                  id="action-phase"
                  aria-label="Phase"
                  value={phase}
                  onChange={setPhase}
                  options={(["pre_deploy", "post_deploy"] as const).map(
                    (p) => ({
                      value: p,
                      label: PHASE_LABEL[p],
                      disabled: readOnly,
                    }),
                  )}
                />
              </Field>
            </FormSection>
            <FormSection title="Settings">
              {kind === "exec" ? (
                <div className="grid gap-1.5">
                  <span className="flex items-center gap-1.5 text-sm font-medium">
                    Command <HelpTip id="hook.argv" />
                  </span>
                  <ArgvField
                    id="action-argv"
                    value={argv}
                    onChange={setArgv}
                    errors={show ? argvErrs : []}
                    disabled={readOnly}
                  />
                </div>
              ) : kind === "restart" ? (
                <div className="grid gap-2">
                  <Field
                    id="action-target"
                    label="Target"
                    help="hook.target"
                    error={show ? targetError : null}
                  >
                    <div className="flex gap-2">
                      <Input
                        id="action-target"
                        value={restartTarget}
                        placeholder="docker:nginx or systemd:nginx.service"
                        autoComplete="off"
                        spellCheck={false}
                        className="font-mono"
                        disabled={readOnly}
                        onChange={(e) => setRestartTarget(e.target.value)}
                      />
                      {!readOnly && (
                        <Button
                          type="button"
                          variant="outline"
                          aria-expanded={browse}
                          onClick={() => setBrowse((b) => !b)}
                        >
                          Browse
                        </Button>
                      )}
                    </div>
                  </Field>
                  {browse && !readOnly && (
                    <RestartTargetPicker
                      orgId={orgId}
                      onPick={(t) => {
                        setRestartTarget(t);
                        setBrowse(false);
                      }}
                    />
                  )}
                </div>
              ) : (
                <div className="grid gap-1.5">
                  <SchemaForm
                    key={kind}
                    ref={formRef}
                    schema={schema}
                    value={config}
                    onChange={(v) => {
                      setConfig(v);
                      setExtra(null);
                    }}
                    storedSecrets={stored}
                    readonly={readOnly}
                    extraErrors={extra ?? undefined}
                    uiSchemaOverrides={uiOverrides}
                    formContext={formContext}
                    columns={2}
                  />
                </div>
              )}
            </FormSection>
            <FormSection title="Limits" columns={2}>
              <Field
                id="action-timeout"
                label="Timeout"
                help="hook.timeout"
                error={show ? timeoutError : null}
              >
                <div className="flex items-center gap-2">
                  <Input
                    id="action-timeout"
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
              {meta.runsOn !== "agent" && (
                <SwitchField
                  id="action-optional"
                  label="Optional"
                  help="action.optional"
                  checked={optional}
                  onCheckedChange={setOptional}
                  onText="Failure does not fail the deploy"
                  offText="Failure fails the deploy"
                  disabled={readOnly}
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
              <Button disabled={saving} onClick={() => void submit()}>
                Save
              </Button>
            </>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
