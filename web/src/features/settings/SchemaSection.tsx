import { useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { RJSFSchema } from '@rjsf/utils';
import { settingsQuery, useSaveSettings, type SectionId } from '@/api/queries/settings';
import { errorMessage } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { withSecretSentinels } from '@/forms/uiSchema';

/** Renders a settings section straight from its server schema: General
 * (baseUrl) and Backup's kekEscrowConfirmed switch (preflight A7). Neither
 * has a secret field today; withSecretSentinels is a no-op then and keeps
 * this generic if one is added later. */
export function SchemaSection({ section }: { section: SectionId }) {
  const q = useQuery(settingsQuery(section));
  const save = useSaveSettings(section);
  const formRef = useRef<SchemaFormHandle>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);

  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  if (q.isError) return <p role="alert">{errorMessage(q.error)}</p>;
  const schema = q.data.schema as RJSFSchema;
  const value = draft ?? withSecretSentinels(schema, q.data.value ?? {});
  const editable = Object.values(schema.properties ?? {}).some((p) => typeof p === 'object' && !p.readOnly);

  return (
    <div className="grid max-w-[720px] gap-6">
      <SchemaForm ref={formRef} schema={schema} value={value} onChange={setDraft} readonly={!editable} />
      {editable && (
        <div className="flex gap-2">
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
        </div>
      )}
    </div>
  );
}
