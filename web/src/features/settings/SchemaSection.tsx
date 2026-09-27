import { useRef, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { settingsQuery, useSaveSettings, type SectionId } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage, withSecretSentinels } from '@/forms/uiSchema';
import { HelpTip } from '@/components/HelpTip';
import type { HelpKey } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';

/** Renders a settings section straight from its server schema: General
 * (baseUrl), Backup's kekEscrowConfirmed switch (preflight A7), and
 * Authentication's OIDC form. Secret properties arrive as `storedSecrets`
 * and are sent back as "__unchanged__" unless replaced. `actions` renders
 * extra buttons (Authentication's "Test connection") next to Save, given
 * the form's current (possibly unsaved) value. Read-only, with no Save,
 * unless the caller holds settings:write.
 *
 * `title`/`help` (Task 9): renders a small heading with a top border above
 * the form when a caller mounts this as its own sub-block rather than the
 * whole section — IssuanceDefaultsSection's Global-tab "Checks and limits"
 * block, under the `issuance` section. */
export function SchemaSection({
  section,
  title,
  help,
  actions,
  uiSchemaOverrides,
}: {
  section: SectionId;
  title?: string;
  help?: HelpKey;
  actions?: (value: Record<string, unknown>) => ReactNode;
  /** Forwarded to `SchemaForm` (fix round 1, Task 10: Agent URL's extra tooltip caveat). */
  uiSchemaOverrides?: UiSchema;
}) {
  const me = useMe();
  const q = useQuery(settingsQuery(section));
  const save = useSaveSettings(section);
  const formRef = useRef<SchemaFormHandle>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [saveError, setSaveError] = useState<ErrorSchema | null>(null);

  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  if (q.isError) return <p role="alert">{errorMessage(q.error)}</p>;
  const schema = q.data.schema as RJSFSchema;
  const stored = q.data.storedSecrets;
  const value = draft ?? withSecretSentinels(schema, q.data.value ?? {}, stored);
  const editable = can(me, 'settings:write') && Object.values(schema.properties ?? {}).some((p) => typeof p === 'object' && !p.readOnly);

  return (
    <div className="grid max-w-[720px] gap-6">
      {title && (
        <div className="flex items-center gap-1.5 border-t pt-4">
          <h3 className="text-sm font-medium">{title}</h3>
          {help && <HelpTip id={help} />}
        </div>
      )}
      <SchemaForm
        ref={formRef}
        schema={schema}
        value={value}
        onChange={(v) => { setDraft(v); setSaveError(null); }}
        storedSecrets={stored}
        readonly={!editable}
        extraErrors={saveError ?? undefined}
        uiSchemaOverrides={uiSchemaOverrides}
      />
      {editable && (
        <div className="flex flex-wrap gap-2">
          <Button
            disabled={!draft || save.isPending}
            onClick={async () => {
              if (!formRef.current?.validate()) return;
              try {
                await save.mutateAsync(value);
                setDraft(null);
                setSaveError(null);
              } catch (e) {
                // The mutation's own toast (useSaveSettings isn't silent
                // here) already surfaces the failure with the server's own
                // message, which already names the offending field for
                // these plain schema sections' JSON-Schema-check errors
                // (fix round 1, Take now #6) — this additionally highlights
                // that field inline, when the message names one. The draft
                // stays either way so nothing typed is lost.
                setSaveError(fieldErrorFromMessage(schema, errorMessage(e)));
              }
            }}
          >
            Save
          </Button>
          {draft && (
            <Button variant="ghost" onClick={() => { setDraft(null); setSaveError(null); }}>
              Discard changes
            </Button>
          )}
          {actions?.(value)}
        </div>
      )}
    </div>
  );
}
