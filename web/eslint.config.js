import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';
import { defineConfig, globalIgnores } from 'eslint/config';

const msgCheckbox = 'Native checkboxes are not allowed. Use SwitchField or ChipSet (spec: Controls).';
const msgRadio = 'Native radio buttons are not allowed. Use SegmentedControl (spec: Controls).';

export default defineConfig([
  globalIgnores(['dist', 'src/routeTree.gen.ts', 'src/api/schema.d.ts', 'playwright-report', 'test-results']),
  {
    files: ['**/*.{ts,tsx,js}'],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2022, globals: { ...globals.browser, ...globals.node } },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'no-restricted-syntax': [
        'error',
        { selector: 'JSXAttribute[name.name="type"][value.value="checkbox"]', message: msgCheckbox },
        { selector: 'JSXAttribute[name.name="type"][value.value="radio"]', message: msgRadio },
        { selector: 'JSXAttribute[name.name="type"] > JSXExpressionContainer > Literal[value="checkbox"]', message: msgCheckbox },
        { selector: 'JSXAttribute[name.name="type"] > JSXExpressionContainer > Literal[value="radio"]', message: msgRadio },
        { selector: 'JSXAttribute[name.name="type"] > JSXExpressionContainer > TemplateLiteral[expressions.length=0][quasis.0.value.raw="checkbox"]', message: msgCheckbox },
        { selector: 'JSXAttribute[name.name="type"] > JSXExpressionContainer > TemplateLiteral[expressions.length=0][quasis.0.value.raw="radio"]', message: msgRadio },
        { selector: 'JSXSpreadAttribute > ObjectExpression > Property[key.name="type"][value.value="checkbox"]', message: msgCheckbox },
        { selector: 'JSXSpreadAttribute > ObjectExpression > Property[key.name="type"][value.value="radio"]', message: msgRadio },
      ],
    },
  },
  { files: ['src/forms/theme/**', '**/*.test.{ts,tsx}'], rules: { '@typescript-eslint/no-explicit-any': 'off' } },
]);
