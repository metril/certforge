import { forwardRef, useImperativeHandle, useMemo, useRef } from 'react';
import type Form from '@rjsf/core';
import { withTheme } from '@rjsf/core';
import type { RJSFSchema } from '@rjsf/utils';
import { customizeValidator } from '@rjsf/validator-ajv8';
import Ajv2020 from 'ajv/dist/2020';
import { shadcnTheme } from './theme';
import { buildUiSchema } from './uiSchema';

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
      onChange={(e) => onChange((e.formData ?? {}) as Record<string, unknown>)}
    />
  );
});
