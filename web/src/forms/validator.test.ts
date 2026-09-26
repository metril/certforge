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
