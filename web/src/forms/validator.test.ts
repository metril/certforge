import type { RJSFSchema } from '@rjsf/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createValidator } from './validator';

// The bug this validator fixes (validator-fix report): @rjsf/validator-ajv8
// compiles schemas via ajv, which calls `new Function` to generate a
// validation function. The server's CSP is `script-src 'self'` with no
// `unsafe-eval`, so in a real browser that throws an uncaught `EvalError`
// and SchemaForm's Save silently no-ops; jsdom has no CSP, so the previous
// tests never caught it. Stubbing `Function` to throw reproduces that CSP
// failure here: if the validator ever calls `new Function` or `eval`,
// validateFormData/isValid below throw instead of returning normally.
describe('cfworker-based validator never uses Function/eval', () => {
  const OriginalFunction = globalThis.Function;

  afterEach(() => {
    globalThis.Function = OriginalFunction;
  });

  function stubFunctionConstructor() {
    // A CSP `script-src 'self'` blocks both `new Function(...)` and
    // indirect `eval`; browsers surface this as the constructor call itself
    // throwing an EvalError, which is what this stub reproduces.
    const blocked = function () {
      throw new EvalError("Refused to evaluate a string as JavaScript because 'unsafe-eval' is not an allowed source of script");
    } as unknown as FunctionConstructor;
    globalThis.Function = blocked;
  }

  const schema: RJSFSchema = {
    type: 'object',
    required: ['name'],
    properties: {
      name: { type: 'string', minLength: 2 },
      site: { type: 'string', format: 'uri' },
    },
  };

  it('validateFormData runs to completion with Function stubbed to throw', () => {
    stubFunctionConstructor();
    const validator = createValidator();
    const { errors } = validator.validateFormData({ name: 'a', site: 'not a uri' }, schema);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('isValid runs to completion with Function stubbed to throw', () => {
    stubFunctionConstructor();
    const validator = createValidator();
    expect(validator.isValid(schema, { name: 'ok', site: 'https://example.com' }, schema)).toBe(true);
    expect(validator.isValid(schema, { name: 'a', site: 'not a uri' }, schema)).toBe(false);
  });

  it('rawValidation runs to completion with Function stubbed to throw', () => {
    stubFunctionConstructor();
    const validator = createValidator();
    const { errors, validationError } = validator.rawValidation(schema, { name: 'a' });
    expect(validationError).toBeUndefined();
    expect(errors?.length).toBeGreaterThan(0);
  });

  it('never constructs a Function or calls eval directly (spy, not just the stub above)', () => {
    // Spying on globalThis.Function/eval directly isn't well-typed by vi.spyOn's overloads.
    const g = globalThis as any;
    const functionSpy = vi.spyOn(g, 'Function');
    const evalSpy = vi.spyOn(g, 'eval');
    const validator = createValidator();
    validator.validateFormData({ name: 'ab', site: 'https://example.com' }, schema);
    validator.isValid(schema, { name: 'ab' }, schema);
    expect(functionSpy).not.toHaveBeenCalled();
    expect(evalSpy).not.toHaveBeenCalled();
    functionSpy.mockRestore();
    evalSpy.mockRestore();
  });
});

// fix round 1, finding 2 (pinning): `toRJSFError`'s `required` handling
// extracts the missing property's name from cfworker's fixed message
// template (`Instance does not have required property "X".`) with a regex;
// this pins that extraction so a future cfworker upgrade that reworded the
// template would fail loudly here instead of silently losing
// `params.missingProperty`/the field association.
it('extracts missingProperty and the field property path from a required error', () => {
  const validator = createValidator();
  const { errors } = validator.validateFormData({}, { type: 'object', required: ['name'] } as RJSFSchema);
  expect(errors).toHaveLength(1);
  expect(errors[0]).toMatchObject({ name: 'required', property: 'name', params: { missingProperty: 'name' } });
});

// Task 9 (Issuance's rateLimits): additionalProperties: false at a nested
// level, with a failing sibling, used to leak a redundant "False boolean
// schema." error onto the failing property (and again one level up, onto
// its parent object) — cfworker's own additionalProperties handling
// re-validates a property against `false` whenever it wasn't marked
// evaluated, which includes one that's declared in `properties` but simply
// failed its own schema (validate.js only marks it evaluated on success).
describe('additionalProperties: false does not leak a redundant "False boolean schema." unit', () => {
  const schema = {
    type: 'object',
    additionalProperties: false,
    properties: {
      rateLimits: {
        type: 'object',
        additionalProperties: false,
        properties: { failedValidationsPerHour: { type: 'integer', minimum: 0 } },
      },
    },
  } as RJSFSchema;

  it('a failing nested property reports only its own real error, not a "false" companion at its own or its parent\'s location', () => {
    const validator = createValidator();
    const { errors } = validator.validateFormData({ rateLimits: { failedValidationsPerHour: -1 } }, schema);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ property: '.rateLimits.failedValidationsPerHour', message: 'Must be at least 0.' });
  });

  it('a genuinely unknown property still fails additionalProperties: false', () => {
    const validator = createValidator();
    const { errors } = validator.validateFormData({ rateLimits: { failedValidationsPerHour: 0 }, extraneous: 'x' }, schema);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ name: 'false', property: '.extraneous' });
  });
});

describe('reworded messages for the common keywords', () => {
  it('pattern includes the pattern text', () => {
    const validator = createValidator();
    const { errors } = validator.validateFormData({ code: 'x' }, { type: 'object', properties: { code: { type: 'string', pattern: '^[A-Z]{3}$' } } } as RJSFSchema);
    expect(errors[0]?.message).toBe('String does not match pattern "^[A-Z]{3}$".');
  });

  it('enum lists the allowed values', () => {
    const validator = createValidator();
    const { errors } = validator.validateFormData({ mode: 'z' }, { type: 'object', properties: { mode: { type: 'string', enum: ['a', 'b'] } } } as RJSFSchema);
    expect(errors[0]?.message).toBe('Must be one of: a, b.');
  });

  it('minimum/maximum/minLength/maxLength read naturally', () => {
    const validator = createValidator();
    const numSchema = { type: 'object', properties: { n: { type: 'integer', minimum: 5, maximum: 10 } } } as RJSFSchema;
    expect(validator.validateFormData({ n: 1 }, numSchema).errors[0]?.message).toBe('Must be at least 5.');
    expect(validator.validateFormData({ n: 20 }, numSchema).errors[0]?.message).toBe('Must be at most 10.');
    const strSchema = { type: 'object', properties: { s: { type: 'string', minLength: 3, maxLength: 5 } } } as RJSFSchema;
    expect(validator.validateFormData({ s: 'a' }, strSchema).errors[0]?.message).toBe('Must be at least 3 characters long.');
    expect(validator.validateFormData({ s: 'abcdef' }, strSchema).errors[0]?.message).toBe('Must be at most 5 characters long.');
  });
});
