import { screen } from '@testing-library/react';
import type { RJSFSchema } from '@rjsf/utils';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { omitFields } from '@/lib/targets';
import { SchemaForm } from './SchemaForm';

// The API decodes each schema into a Go map, so `properties` arrives sorted
// alphabetically; `x-order` carries the author's order (internal/api/meta.go).
const pfsense = {
  type: 'object',
  'x-order': ['url', 'username', 'password', 'certName', 'caPem'],
  properties: {
    caPem: { type: 'string', title: 'CA certificate' },
    certName: { type: 'string', title: 'Certificate name' },
    password: { type: 'string', title: 'Password', secret: true },
    url: { type: 'string', title: 'API URL' },
    username: { type: 'string', title: 'Username' },
  },
} as RJSFSchema;

function labels(): string[] {
  return Array.from(document.querySelectorAll('label')).map((l) => l.textContent?.replace(/Optional/, '').trim() ?? '');
}

it('renders fields in schema order: Username immediately before Password', () => {
  renderUI(<SchemaForm schema={pfsense} value={{}} onChange={() => {}} />);
  const ls = labels();
  expect(ls.indexOf('Username')).toBeGreaterThan(-1);
  expect(ls.indexOf('Password')).toBe(ls.indexOf('Username') + 1);
  expect(ls[0]).toBe('API URL');
  expect(screen.getByLabelText(/Username/)).toBeInTheDocument();
});

it('keeps the order when a saved credential hides fields', () => {
  const schema = omitFields(pfsense, ['url']);
  renderUI(<SchemaForm schema={schema} value={{}} onChange={() => {}} />);
  const ls = labels();
  expect(ls.indexOf('Password')).toBe(ls.indexOf('Username') + 1);
});
