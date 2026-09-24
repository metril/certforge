// @vitest-environment node
import { ESLint } from 'eslint';
import { describe, expect, it } from 'vitest';

const eslint = new ESLint({ cwd: process.cwd() });

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
