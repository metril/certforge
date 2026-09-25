import { forwardRef, useImperativeHandle, useMemo, useRef } from 'react';
import type Form from '@rjsf/core';
import { withTheme } from '@rjsf/core';
import type { RJSFSchema } from '@rjsf/utils';
import { customizeValidator } from '@rjsf/validator-ajv8';
import Ajv2020 from 'ajv/dist/2020';
import { shadcnTheme } from './theme';
import { buildUiSchema, serverPathKeys } from './uiSchema';

const ThemedForm = withTheme(shadcnTheme);

// Adaptation (preflight A11, Critical): every committed provider schema
// (internal/challenge/schemas/*.json) declares draft 2020-12
// ($schema: https://json-schema.org/draft/2020-12/schema). The default
// @rjsf/validator-ajv8 validator builds a draft-07 Ajv instance, which fails
// to compile a 2020-12 schema; validateForm() then always returns false with
// no visible error (ErrorListTemplate renders nothing), so a credential form
// could never be submitted. Building the validator with the 2020-12 Ajv
// class fixes this; @rjsf/validator-ajv8's default `strict: false` (see its
// createAjvInstance) means the schemas' non-standard `secret`/`serverPath`/
// `unsupported`/`unsupportedReason` keywords are ignored rather than
// rejected.
const validator = customizeValidator({ AjvClass: Ajv2020 });

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
};

export const SchemaForm = forwardRef<SchemaFormHandle, Props>(function SchemaForm({ schema, value, onChange, storedSecrets, readonly = false }, ref) {
  const formRef = useRef<Form>(null);
  const uiSchema = useMemo(() => buildUiSchema(schema, { storedSecrets }), [schema, storedSecrets]);
  const serverPath = useMemo(() => serverPathKeys(schema), [schema]);
  useImperativeHandle(ref, () => ({ validate: () => formRef.current?.validateForm() ?? false }), []);
  return (
    <ThemedForm
      ref={formRef}
      schema={schema}
      uiSchema={uiSchema}
      formData={value}
      validator={validator}
      readonly={readonly}
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
