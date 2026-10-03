import { Card, CardBody, CardHeader } from '@/components/Card';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { saveSettingsDirect, settingsQuery, useSaveSettings, type SectionId } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage, withSecretSentinels } from '@/forms/uiSchema';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import type { HelpKey } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';

/** Renders a settings section straight from its server schema: General
 * (baseUrl), Backup's schedule form, and
 * Authentication's OIDC form. Secret properties arrive as `storedSecrets`
 * and are sent back as "__unchanged__" unless replaced. `actions` renders
 * extra buttons (Authentication's "Test connection") next to Save, given
 * the form's current (possibly unsaved) value. The form itself is read-only
 * without settings:write; Save stays visible but disabled behind
 * `PermissionTip` (review fix round 1, Task 9 — global-constraints: a
 * control the caller cannot use is shown disabled, never hidden, exactly
 * like IssuanceDefaultsSection's own "Save global defaults"/"Save org
 * defaults" buttons). `actions` and Discard still only show for a writer:
 * Discard because a read-only form never produces a draft to discard, and
 * `actions` (e.g. Authentication's "Test connection") because it isn't the
 * write control this ruling is about.
 *
 * `title`/`help` (Task 9): renders a small heading with a top border above
 * the form when a caller mounts this as its own sub-block rather than the
 * whole section — IssuanceDefaultsSection's Global-tab "Checks and limits"
 * block, under the `issuance` section. It renders before the loading/error
 * states below too, so the heading doesn't pop in only once data arrives. */
export function SchemaSection({
  section,
  title,
  help,
  actions,
  uiSchemaOverrides,
  saveMode,
  mapSaveError,
  prepareBody,
  onSaved,
  onDirtyChange,
}: {
  section: SectionId;
  title?: string;
  help?: HelpKey;
  /** `state.dirty` (Task 6): true while there's an unsaved draft — Email's
   * own Send test email uses it to disable itself and explain why (Review
   * Focus, "Tests against unsaved drafts"), the same way Task 3's
   * ChannelTest already does with its own `dirty` prop. Existing callers
   * that only destructure `value` are unaffected: a function type is
   * assignable to one with fewer declared parameters. */
  actions?: (value: Record<string, unknown>, state: { dirty: boolean }) => ReactNode;
  /** Forwarded to `SchemaForm` (fix round 1, Task 10: Agent URL's extra
   * tooltip caveat). A function form (Task 6: Vault's token/roleId/secretId
   * hidden by the live `authMethod`) is re-evaluated against the section's
   * current (possibly unsaved) value on every render, the same live draft
   * `actions` already receives. */
  uiSchemaOverrides?: UiSchema | ((value: Record<string, unknown>) => UiSchema);
  /** 'direct' (Task 6): saves through `saveSettingsDirect` instead of
   * `useSaveSettings`'s `useMutation` — the Vault section's `token`/
   * `secretId` must never sit in the mutation cache (global constraints,
   * "Secrets"). The query cache is invalidated the same way either mode
   * would, so the form still shows the freshly-saved value afterward. */
  saveMode?: 'direct';
  /** Batch 3 review (Critical, SchemaSection.tsx:150): overrides the
   * default `fieldErrorFromMessage(schema, message)` mapping of a failed
   * save's error onto a schema property. Vault's own "re-enter the token"
   * 422 names `token` literally, but `token` is hidden under `authMethod:
   * 'approle'` — IntegrationsSection maps it to whichever secret field is
   * actually visible instead. Receives the live (possibly-unsaved) value
   * so the mapper can consult sibling fields such as `authMethod`. */
  mapSaveError?: (message: string, value: Record<string, unknown>, schema: RJSFSchema) => ErrorSchema | null;
  /** Batch 3 review (Critical, IntegrationsSection.tsx:28): transforms the
   * value right before it's sent to Save (both `saveSettingsDirect` and
   * `useSaveSettings`), without touching what's rendered or held as the
   * draft. Vault's own `token`/`roleId`/`secretId` are hidden by
   * `authMethod` but stay in `value` (so switching `authMethod` back
   * doesn't lose what was typed) — the server's `checkSettings` 422s if the
   * *other* method's field is present at all, even as the `__unchanged__`
   * sentinel, so IntegrationsSection drops it here before the request. */
  prepareBody?: (value: Record<string, unknown>) => Record<string, unknown>;
  /** Runs after a successful save, direct or mutation (Task 6, for Task 7's
   * later use) — after the draft and any save error are cleared. */
  onSaved?: () => void;
  /** Reports whether an unsaved draft exists (for a caller's leave-page guard). */
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery(settingsQuery(section));
  const save = useSaveSettings(section);
  const [savingDirect, setSavingDirect] = useState(false);
  const formRef = useRef<SchemaFormHandle>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [saveError, setSaveError] = useState<ErrorSchema | null>(null);
  const canWrite = can(me, 'settings:write');
  const hasDraft = draft !== null;
  useEffect(() => onDirtyChange?.(hasDraft), [hasDraft, onDirtyChange]);

  const heading = title && (
    <CardHeader
      title={
        <span className="flex items-center gap-1.5">
          {title}
          {help && <HelpTip id={help} />}
        </span>
      }
    />
  );

  if (q.isPending) {
    return (
      <Card className="max-w-[720px]">
        {heading}
        <CardBody>
          <p className="text-ink-muted">Loading…</p>
        </CardBody>
      </Card>
    );
  }
  if (q.isError) {
    return (
      <Card className="max-w-[720px]">
        {heading}
        <CardBody>
          <p role="alert">{errorMessage(q.error)}</p>
        </CardBody>
      </Card>
    );
  }
  const schema = q.data.schema as RJSFSchema;
  const stored = q.data.storedSecrets;
  const dirty = draft !== null;
  const value = draft ?? withSecretSentinels(schema, q.data.value ?? {}, stored);
  const resolvedUiSchemaOverrides = typeof uiSchemaOverrides === 'function' ? uiSchemaOverrides(value) : uiSchemaOverrides;
  // A schema with nothing writable at all (every property readOnly) has no
  // Save button regardless of permission — there's genuinely nothing to
  // persist. Otherwise the block always renders; `canWrite` alone decides
  // whether the form and Save are usable, not whether they're shown.
  const hasWritableField = Object.values(schema.properties ?? {}).some((p) => typeof p === 'object' && !p.readOnly);

  return (
    <Card className="max-w-[720px]">
      {heading}
      <CardBody className="grid gap-6">
      <SchemaForm
        ref={formRef}
        schema={schema}
        value={value}
        onChange={(v) => { setDraft(v); setSaveError(null); }}
        storedSecrets={stored}
        readonly={!canWrite}
        extraErrors={saveError ?? undefined}
        uiSchemaOverrides={resolvedUiSchemaOverrides}
      />
      {hasWritableField && (
        <div className="flex flex-wrap gap-2">
          <PermissionTip allowed={canWrite} action="settings:write">
            <Button
              disabled={!canWrite || !draft || save.isPending || savingDirect}
              onClick={async () => {
                if (!formRef.current?.validate()) return;
                const body = prepareBody ? prepareBody(value) : value;
                try {
                  if (saveMode === 'direct') {
                    setSavingDirect(true);
                    try {
                      await saveSettingsDirect(section, body);
                      await qc.invalidateQueries({ queryKey: ['settings', section] });
                      toast.success('Settings saved');
                    } finally {
                      setSavingDirect(false);
                    }
                  } else {
                    await save.mutateAsync(body);
                  }
                  setDraft(null);
                  setSaveError(null);
                  onSaved?.();
                } catch (e) {
                  // The mutation's own toast (useSaveSettings isn't silent
                  // here) already surfaces the failure with the server's own
                  // message, which already names the offending field for
                  // these plain schema sections' JSON-Schema-check errors
                  // (fix round 1, Take now #6) — this additionally highlights
                  // that field inline, when the message names one. The draft
                  // stays either way so nothing typed is lost. Direct mode
                  // (Task 6) has no mutation cache to surface its own toast,
                  // so it's shown here explicitly, same message either way.
                  const message = errorMessage(e);
                  if (saveMode === 'direct') toast.error(message);
                  setSaveError(mapSaveError ? mapSaveError(message, value, schema) : fieldErrorFromMessage(schema, message));
                }
              }}
            >
              Save
            </Button>
          </PermissionTip>
          {draft && (
            <Button variant="ghost" onClick={() => { setDraft(null); setSaveError(null); }}>
              Discard changes
            </Button>
          )}
          {/* Task 6 (review focus: "a control the caller cannot use is shown
              disabled, never hidden"): SchemaSection no longer hides actions
              for a non-writer itself — Vault's own Test connection stays
              visible-but-disabled behind its own PermissionTip.
              AuthenticationSection's Test connection keeps its pre-5B hidden
              behavior by returning null from its own `actions` callback. */}
          {actions?.(value, { dirty })}
        </div>
      )}
      </CardBody>
    </Card>
  );
}
