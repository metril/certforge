import { useRef, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { RJSFSchema } from '@rjsf/utils';
import { settingsQuery, useSaveSettings, type SectionId } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { withSecretSentinels } from '@/forms/uiSchema';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';

/** Renders a settings section straight from its server schema: General
 * (baseUrl), Backup's kekEscrowConfirmed switch (preflight A7), and
 * Authentication's OIDC form. Secret properties arrive as `storedSecrets`
 * and are sent back as "__unchanged__" unless replaced. `actions` renders
 * extra buttons (Authentication's "Test connection") next to Save, given
 * the form's current (possibly unsaved) value. Read-only, with no Save,
 * unless the caller holds settings:write. */
export function SchemaSection({ section, actions }: { section: SectionId; actions?: (value: Record<string, unknown>) => ReactNode }) {
  const me = useMe();
  const q = useQuery(settingsQuery(section));
  const save = useSaveSettings(section);
  const formRef = useRef<SchemaFormHandle>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);

  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  if (q.isError) return <p role="alert">{errorMessage(q.error)}</p>;
  const schema = q.data.schema as RJSFSchema;
  const stored = q.data.storedSecrets;
  const value = draft ?? withSecretSentinels(schema, q.data.value ?? {}, stored);
  const editable = can(me, 'settings:write') && Object.values(schema.properties ?? {}).some((p) => typeof p === 'object' && !p.readOnly);

  return (
    <div className="grid max-w-[720px] gap-6">
      <SchemaForm ref={formRef} schema={schema} value={value} onChange={setDraft} storedSecrets={stored} readonly={!editable} />
      {editable && (
        <div className="flex flex-wrap gap-2">
          <Button
            disabled={!draft || save.isPending}
            onClick={async () => {
              if (!formRef.current?.validate()) return;
              try {
                await save.mutateAsync(value);
                setDraft(null);
              } catch {
                // The mutation's own toast (useSaveSettings isn't silent
                // here) already surfaces the failure; the draft stays so
                // nothing typed is lost.
              }
            }}
          >
            Save
          </Button>
          {draft && (
            <Button variant="ghost" onClick={() => setDraft(null)}>
              Discard changes
            </Button>
          )}
          {actions?.(value)}
        </div>
      )}
    </div>
  );
}
