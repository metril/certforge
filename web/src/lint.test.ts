// @vitest-environment node
import { ESLint } from 'eslint';
import { describe, expect, it } from 'vitest';

// The fixture is not part of the tsconfig, so the type-aware rule is switched off for it.
const eslint = new ESLint({
  cwd: process.cwd(),
  overrideConfig: [{ files: ['src/**/*.{ts,tsx}'], languageOptions: { parserOptions: { project: null } }, rules: { '@typescript-eslint/no-floating-promises': 'off' } }],
});

async function restricted(code: string) {
  const [result] = await eslint.lintText(code, { filePath: 'src/__lint_fixture__.tsx' });
  return result!.messages.filter((m) => m.ruleId === 'no-restricted-syntax');
}

describe('native choice inputs are blocked', () => {
  it.each([
    '<input type="checkbox" />',
    '<input type="radio" />',
    '<input type={"checkbox"} />',
    '<input type={`checkbox`} />',
    '<input type={`radio`} />',
    '<input {...{ type: "checkbox" }} />',
    '<input {...{ type: "radio" }} />',
  ])('%s', async (jsx) => {
    expect(await restricted(`export const X = () => ${jsx};`)).toHaveLength(1);
  });
  it('allows text inputs', async () => {
    expect(await restricted('export const X = () => <input type="text" />;')).toHaveLength(0);
  });
});
