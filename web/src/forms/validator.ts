import { Validator as CFValidator, type OutputUnit, type Schema as CFSchema, type SchemaDraft } from '@cfworker/json-schema';
import {
  createErrorHandler,
  getDefaultFormState,
  toErrorSchema,
  unwrapErrorHandler,
  validationDataMerge,
  type CustomValidator,
  type ErrorTransformer,
  type FormContextType,
  type RJSFSchema,
  type RJSFValidationError,
  type StrictRJSFSchema,
  type UiSchema,
  type ValidationData,
  type ValidatorType,
} from '@rjsf/utils';

// Adaptation (validator-fix): every committed provider schema
// (internal/challenge/schemas/*.json) and internal/issuance/defaults.schema.json
// declares draft 2020-12 ($schema: https://json-schema.org/draft/2020-12/schema),
// and no schema rendered through SchemaForm uses an older draft, so the
// interpreter is fixed to 2020-12 rather than sniffed per schema.
const DRAFT: SchemaDraft = '2020-12';

function decodePointerSegment(segment: string): string {
  return segment.replace(/~1/g, '/').replace(/~0/g, '~');
}

/**
 * Converts a cfworker `instanceLocation` JSON pointer (e.g. `#/a/b/0`) into
 * the dotted/bracketed property path RJSF expects (`.a.b[0]`), matching what
 * `@rjsf/validator-ajv8` produces from ajv's `instancePath` so downstream
 * consumers (`toErrorSchema`, `toPath`) resolve fields the same way.
 */
function propertyFromInstanceLocation(instanceLocation: string): string {
  const path = instanceLocation.replace(/^#/, '');
  if (!path) return '';
  const segments = path
    .split('/')
    .filter((s) => s.length > 0)
    .map(decodePointerSegment);
  let out = '';
  for (const segment of segments) {
    out += /^\d+$/.test(segment) ? `[${segment}]` : `.${segment}`;
  }
  return out;
}

const REQUIRED_PROPERTY_RE = /Instance does not have required property "(.*)"\.$/;

/**
 * Maps one cfworker `OutputUnit` to an RJSF `RJSFValidationError`, mirroring
 * `@rjsf/validator-ajv8`'s `transformRJSFValidationErrors` closely enough for
 * this app's needs: FieldTemplate (theme/templates.tsx) only ever reads
 * `rawErrors[0]` (a plain message string) once `toErrorSchema` has grouped
 * errors by field, so the property path is what has to be exactly right; the
 * richer `title`-substitution ajv8 does in its `message`/`stack` is skipped.
 */
function toRJSFError(unit: OutputUnit): RJSFValidationError {
  let property = propertyFromInstanceLocation(unit.instanceLocation);
  const params: Record<string, unknown> = { keyword: unit.keyword };
  if (unit.keyword === 'required') {
    const missing = REQUIRED_PROPERTY_RE.exec(unit.error)?.[1];
    if (missing) {
      params.missingProperty = missing;
      // ajv8's own convention (ValidationError's instancePath.replace('/', '.')
      // then appending missingProperty): no leading dot at the root.
      property = property ? `${property}.${missing}` : missing;
    }
  }
  const message = unit.error;
  const stack = `${property} ${message}`.trim();
  return {
    name: unit.keyword,
    property,
    message,
    params,
    stack,
    schemaPath: unit.keywordLocation,
  };
}

/**
 * Merges `rootSchema`'s `$defs`/`definitions` into `schema` so a `$ref` in a
 * subschema (e.g. one `oneOf` branch) can still resolve against the root
 * schema's definitions when validated on its own via `isValid` — mirroring
 * why `@rjsf/validator-ajv8`'s `isValid` registers `rootSchema` with ajv
 * before compiling `schema`. None of this app's schemas currently use
 * `$ref`/`$defs`, so this is defensive rather than exercised.
 */
function withRootDefs(schema: CFSchema, rootSchema?: CFSchema): CFSchema {
  if (!rootSchema || typeof rootSchema !== 'object') return schema;
  const defs = { ...(rootSchema.$defs ?? {}), ...(rootSchema.definitions ?? {}) };
  if (Object.keys(defs).length === 0) return schema;
  if (typeof schema !== 'object') return schema;
  return { $defs: { ...defs, ...(schema.$defs ?? {}) }, ...schema };
}

/**
 * A `ValidatorType` implementation built on `@cfworker/json-schema`, a pure
 * JSON Schema interpreter with no `new Function`/`eval` codegen. It replaces
 * `@rjsf/validator-ajv8`: ajv compiles schemas via `new Function`, which the
 * server's CSP (`script-src 'self'`, internal/api/router.go, no
 * `unsafe-eval`) blocks in a real browser, so every SchemaForm validation
 * threw an uncaught `EvalError` and silently no-opped (jsdom has no CSP, so
 * the unit/component tests never caught it — only the Playwright spec did).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- FormContextType (@rjsf/utils) is Record<string, any>; `any` is its own default too.
class CfworkerValidator<T = unknown, S extends StrictRJSFSchema = RJSFSchema, F extends FormContextType = any>
  implements ValidatorType<T, S, F>
{
  rawValidation<Result = OutputUnit>(schema: S, formData?: T): { errors?: Result[]; validationError?: Error } {
    try {
      // dereference() throws on a malformed schema (e.g. a duplicate $id);
      // shortCircuit=false so every failing field is reported at once
      // (shortCircuit=true stops a properties/items loop at the first
      // failure, which would hide every other invalid field).
      const validator = new CFValidator(schema as unknown as CFSchema, DRAFT, false);
      const result = validator.validate(formData);
      return { errors: (result.valid ? [] : result.errors) as unknown as Result[] };
    } catch (err) {
      return { errors: [], validationError: err instanceof Error ? err : new Error(String(err)) };
    }
  }

  validateFormData(
    formData: T | undefined,
    schema: S,
    customValidate?: CustomValidator<T, S, F>,
    transformErrors?: ErrorTransformer<T, S, F>,
    uiSchema?: UiSchema<T, S, F>,
  ): ValidationData<T> {
    const raw = this.rawValidation<OutputUnit>(schema, formData);
    let errors = (raw.errors ?? []).map(toRJSFError);
    if (typeof transformErrors === 'function') {
      errors = transformErrors(errors, uiSchema);
    }
    let errorSchema = toErrorSchema<T>(errors);
    if (raw.validationError) {
      errorSchema = { ...errorSchema, $schema: { __errors: [raw.validationError.message] } };
    }
    if (typeof customValidate !== 'function') {
      return { errors, errorSchema };
    }
    const newFormData = getDefaultFormState(this, schema, formData, schema, true) as T;
    const errorHandler = customValidate(newFormData, createErrorHandler(newFormData), uiSchema, errorSchema);
    const userErrorSchema = unwrapErrorHandler(errorHandler);
    return validationDataMerge({ errors, errorSchema }, userErrorSchema);
  }

  isValid(schema: S, formData: T | undefined, rootSchema: S): boolean {
    try {
      const effective = withRootDefs(schema as unknown as CFSchema, rootSchema as unknown as CFSchema);
      const validator = new CFValidator(effective, DRAFT, false);
      return validator.validate(formData).valid;
    } catch {
      return false;
    }
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- see the class above.
export function createValidator<T = unknown, S extends StrictRJSFSchema = RJSFSchema, F extends FormContextType = any>(): ValidatorType<
  T,
  S,
  F
> {
  return new CfworkerValidator<T, S, F>();
}

export const validator: ValidatorType = createValidator();
