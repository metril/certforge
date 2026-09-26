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
 * cfworker's `shortCircuit=false` (required so every invalid field is
 * reported — see `rawValidation` below) also means a container keyword whose
 * subschema failed emits its OWN summary unit (e.g. `properties`: `Property
 * "dir" does not match schema.`) in addition to the leaf unit that actually
 * explains the failure (e.g. `pattern` on `#/dir`). Left in, that summary
 * lands on the parent's own `instanceLocation` (often the root) and renders
 * as a second, redundant alert with no useful detail. These three sets
 * classify every such wrapper keyword cfworker emits (read from its
 * `validate.ts`) by how its accompanying leaf unit(s) can be found:
 *
 * - `KEYWORD_LOCATION_NESTED`: the wrapper and its leaves share the same
 *   `instanceLocation`, but the leaf's `keywordLocation` is nested under the
 *   wrapper's (`.../properties/dir/pattern` under `.../properties`).
 * - `INSTANCE_LOCATION_NESTED`: the wrapper and its leaves share the same
 *   `keywordLocation` (no per-item suffix), but the leaf's `instanceLocation`
 *   is nested under the wrapper's (per evaluated key/index).
 * - `ALWAYS_WRAPPER`: `if` and `$ref`/`$recursiveRef` branch to a sibling
 *   `keywordLocation` (`.../if` vs `.../then`) at the SAME `instanceLocation`,
 *   so neither of the two structural checks above applies; cfworker only
 *   ever emits these when the branch it names actually failed (guaranteeing
 *   at least one accompanying leaf), so they're unconditionally dropped.
 */
const KEYWORD_LOCATION_NESTED_WRAPPERS = new Set(['properties', 'patternProperties', 'prefixItems', 'items', 'allOf', 'anyOf', 'oneOf', 'dependentSchemas']);
const INSTANCE_LOCATION_NESTED_WRAPPERS = new Set(['additionalProperties', 'unevaluatedProperties', 'additionalItems', 'unevaluatedItems', 'contains', 'propertyNames']);
const ALWAYS_WRAPPER_KEYWORDS = new Set(['if', '$ref', '$recursiveRef']);

/** True if `child` is `parent` plus at least one more JSON-pointer segment. */
function isStrictDescendantPointer(child: string, parent: string): boolean {
  return child !== parent && child.startsWith(parent) && child[parent.length] === '/';
}

function isWrapperUnit(unit: OutputUnit, all: OutputUnit[]): boolean {
  if (ALWAYS_WRAPPER_KEYWORDS.has(unit.keyword)) return true;
  if (KEYWORD_LOCATION_NESTED_WRAPPERS.has(unit.keyword)) {
    return all.some((v) => v !== unit && isStrictDescendantPointer(v.keywordLocation, unit.keywordLocation));
  }
  if (INSTANCE_LOCATION_NESTED_WRAPPERS.has(unit.keyword)) {
    return all.some((v) => v !== unit && isStrictDescendantPointer(v.instanceLocation, unit.instanceLocation));
  }
  return false;
}

/** Drops every wrapper unit (see above), keeping only the leaf units that name the actual failed check. */
function leafUnitsOnly(units: OutputUnit[]): OutputUnit[] {
  return units.filter((unit) => !isWrapperUnit(unit, units));
}

function decodePointer(pointer: string): string[] {
  return pointer
    .replace(/^#/, '')
    .split('/')
    .filter((s) => s.length > 0)
    .map(decodePointerSegment);
}

/** Resolves a cfworker `keywordLocation` (a JSON pointer into the schema that was validated) back to the schema value it names, e.g. a `pattern` unit's own regex source, so the message below can quote it. */
function resolveInSchema(rootSchema: unknown, keywordLocation: string): unknown {
  let cur: unknown = rootSchema;
  for (const key of decodePointer(keywordLocation)) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/**
 * Rewords cfworker's raw message for the keywords this app's schemas hit
 * most, so the field-level error reads naturally and, for `pattern`, actually
 * includes the pattern (cfworker's own text for it — `String does not match
 * pattern.` — omits the regex entirely). Every other keyword's message is
 * left as cfworker produced it.
 */
function rewordMessage(unit: OutputUnit, rootSchema: unknown): string {
  switch (unit.keyword) {
    case 'pattern': {
      const pattern = resolveInSchema(rootSchema, unit.keywordLocation);
      return typeof pattern === 'string' ? `String does not match pattern "${pattern}".` : unit.error;
    }
    case 'enum': {
      const values = resolveInSchema(rootSchema, unit.keywordLocation);
      return Array.isArray(values) ? `Must be one of: ${values.map(String).join(', ')}.` : unit.error;
    }
    case 'minimum': {
      const min = resolveInSchema(rootSchema, unit.keywordLocation);
      return typeof min === 'number' ? `Must be at least ${min}.` : unit.error;
    }
    case 'maximum': {
      const max = resolveInSchema(rootSchema, unit.keywordLocation);
      return typeof max === 'number' ? `Must be at most ${max}.` : unit.error;
    }
    case 'minLength': {
      const min = resolveInSchema(rootSchema, unit.keywordLocation);
      return typeof min === 'number' ? `Must be at least ${min} character${min === 1 ? '' : 's'} long.` : unit.error;
    }
    case 'maxLength': {
      const max = resolveInSchema(rootSchema, unit.keywordLocation);
      return typeof max === 'number' ? `Must be at most ${max} character${max === 1 ? '' : 's'} long.` : unit.error;
    }
    default:
      return unit.error;
  }
}

/**
 * Maps one cfworker `OutputUnit` to an RJSF `RJSFValidationError`, mirroring
 * `@rjsf/validator-ajv8`'s `transformRJSFValidationErrors` closely enough for
 * this app's needs: FieldTemplate (theme/templates.tsx) only ever reads
 * `rawErrors[0]` (a plain message string) once `toErrorSchema` has grouped
 * errors by field, so the property path is what has to be exactly right; the
 * richer `title`-substitution ajv8 does in its `message`/`stack` is skipped.
 */
function toRJSFError(unit: OutputUnit, rootSchema: unknown): RJSFValidationError {
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
  const message = rewordMessage(unit, rootSchema);
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
      return { errors: (result.valid ? [] : leafUnitsOnly(result.errors)) as unknown as Result[] };
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
    let errors = (raw.errors ?? []).map((unit) => toRJSFError(unit, schema));
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
