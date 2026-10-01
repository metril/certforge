import { forwardRef, useImperativeHandle, useMemo, useRef } from 'react';
// Imported from these specific subpaths (rather than the `@rjsf/core`
// barrel) because @rjsf/core's own index.js unconditionally imports
// getTestRegistry.js, which imports @rjsf/validator-ajv8 — a package this
// app no longer installs (see ./validator.ts). Neither withTheme.js nor
// components/Form.js reference that module, so this avoids the dependency
// without patching @rjsf/core itself.
import type Form from '@rjsf/core/lib/components/Form.js';
import withTheme from '@rjsf/core/lib/withTheme.js';
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { shadcnTheme } from './theme';
import { buildUiSchema, serverPathKeys } from './uiSchema';
import { validator } from './validator';

const ThemedForm = withTheme(shadcnTheme);

export type SchemaFormHandle = { validate: () => boolean };

type Props = {
  schema: RJSFSchema;
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  /**
   * Secret field names that already have a stored value (controller ruling,
   * preflight A13/C2: `DNSCredential.storedSecrets`, not a single global
   * "has secrets" boolean). Every field not listed is a new, write-only
   * secret.
   */
  storedSecrets?: string[];
  readonly?: boolean;
  /**
   * A server-side error (fix round 1, Take now #6) mapped to the schema
   * property it names, rendered inline under that field the same way a
   * client-side validation error would be — the caller (e.g. SchemaSection)
   * computes this from the failed save's `ApiError` via
   * `uiSchema.ts`'s `fieldErrorFromMessage`.
   */
  extraErrors?: ErrorSchema;
  /**
   * Per-field `uiSchema` overrides merged over `buildUiSchema`'s own output
   * (fix round 1, Task 10: Settings → Agents needs the Agent URL field's
   * tooltip to add a caveat — that changing it doesn't reach already-
   * enrolled agents — that the server's own schema `description` doesn't
   * carry). Keyed by property name, e.g. `{ agentUrl: { 'ui:description': '...' } }`.
   */
  uiSchemaOverrides?: UiSchema;
  /** Fetches a stored secret's plaintext for the secret widget's reveal
   * button (passed via formContext, never uiSchema — nothing secret in it). */
  onRevealSecret?: (field: string) => Promise<string>;
  revealDisabledReason?: string;
};

export const SchemaForm = forwardRef<SchemaFormHandle, Props>(function SchemaForm({ schema, value, onChange, storedSecrets, readonly = false, extraErrors, uiSchemaOverrides, onRevealSecret, revealDisabledReason }, ref) {
  const formRef = useRef<Form>(null);
  const uiSchema = useMemo(() => {
    const base = buildUiSchema(schema, { storedSecrets });
    if (!uiSchemaOverrides) return base;
    const merged: UiSchema = { ...base };
    for (const [key, override] of Object.entries(uiSchemaOverrides)) {
      // A top-level 'ui:order' (an array) or any other non-object override
      // must pass through as-is: spreading an array into an object (the
      // old unconditional object-merge below) turns it into {0: ..., 1:
      // ...}, which RJSF's ui:order does not understand.
      merged[key] =
        Array.isArray(override) || typeof override !== 'object'
          ? override
          : { ...(typeof base[key] === 'object' ? base[key] : {}), ...override };
    }
    return merged;
  }, [schema, storedSecrets, uiSchemaOverrides]);
  const serverPath = useMemo(() => serverPathKeys(schema), [schema]);
  const formContext = useMemo(() => ({ onRevealSecret, revealDisabledReason }), [onRevealSecret, revealDisabledReason]);
  useImperativeHandle(ref, () => ({ validate: () => formRef.current?.validateForm() ?? false }), []);
  return (
    <ThemedForm
      ref={formRef}
      schema={schema}
      uiSchema={uiSchema}
      formData={value}
      validator={validator}
      readonly={readonly}
      formContext={formContext}
      extraErrors={extraErrors}
      showErrorList={false}
      noHtml5Validate
      // C1: every caller (CredentialSheet, SchemaSection) either wraps this
      // in its own <form> or drives saving from a plain button's onClick,
      // never from this form's native submit; rendering RJSF's own <form>
      // tag too produces an invalid nested <form>-in-<form> (React warns via
      // validateDOMNesting) in the CredentialSheet case. `tagName="div"`
      // keeps every field's markup identical while dropping the extra tag.
      tagName="div"
      // C1: validateForm() (called from the `validate` imperative handle
      // above) runs the same error path RJSF's onSubmit uses; with no
      // onError, RJSF's default logs "Form validation failed" via
      // console.error on every expected, user-visible validation failure.
      // The field-level errors already render inline (FieldTemplate reads
      // the form's own error state), so there's nothing more to do here.
      onError={() => {}}
      onChange={(e) => {
        const data = { ...((e.formData ?? {}) as Record<string, unknown>) };
        // Fix round 1: a serverPath field is server-managed (preflight A10);
        // the API 422s if the client sends one at all. The widget is
        // hidden, so nothing here ever sets it, but an older credential's
        // `config` can still carry a stale value for it, so it's stripped
        // on every change rather than trusting every caller to omit it.
        for (const k of serverPath) delete data[k];
        onChange(data);
      }}
    />
  );
});
