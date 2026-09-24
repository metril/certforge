import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createRef, useState, type Ref } from 'react';
import { act, screen } from '@testing-library/react';
import type { RJSFSchema } from '@rjsf/utils';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { SchemaForm, type SchemaFormHandle } from './SchemaForm';
import { withSecretSentinels } from './uiSchema';

const schema = {
  type: 'object',
  required: ['apiToken', 'mode'],
  properties: {
    apiToken: { type: 'string', title: 'API token', secret: true, description: 'Token with Zone.DNS edit rights. Create it in the dashboard. Third sentence.' },
    mode: { type: 'string', title: 'Mode', enum: ['auto', 'manual', 'none'] },
    proxied: { type: 'boolean', title: 'Proxied', description: 'Send traffic through the proxy.' },
    regions: { type: 'array', title: 'Regions', uniqueItems: true, items: { type: 'string', enum: ['eu', 'us', 'ap'] } },
    endpoint: { type: 'string', title: 'Endpoint', enum: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] },
    ttl: { type: 'integer', title: 'TTL' },
    // preflight A10: server-managed fields (serverPath) never render.
    internalPath: { type: 'string', title: 'Internal path', serverPath: true },
  },
} as RJSFSchema;

function Harness({ storedSecrets, handle }: { storedSecrets?: string[]; handle?: Ref<SchemaFormHandle> }) {
  const [v, setV] = useState<Record<string, unknown>>(storedSecrets ? withSecretSentinels(schema, {}, storedSecrets) : {});
  return <SchemaForm ref={handle} schema={schema} value={v} onChange={setV} storedSecrets={storedSecrets} />;
}

it('maps schema types to spec controls, renders no native checkbox or radio, and hides serverPath fields', () => {
  const { container } = renderUI(<Harness />);
  // Radix's Switch renders its own hidden (aria-hidden) native checkbox to
  // bubble change events to a surrounding <form>; that's an internal detail
  // of the vetted primitive, not markup this app authored, so it's excluded
  // from the "no native checkbox/radio" spec rule (ESLint enforces the rule
  // against JSX we write, not a dependency's shadow DOM).
  expect(container.querySelectorAll('input[type="checkbox"]:not([aria-hidden="true"]), input[type="radio"]:not([aria-hidden="true"])')).toHaveLength(0);
  expect(screen.getByRole('radio', { name: 'auto' })).toBeInTheDocument();
  expect(screen.getByRole('switch', { name: 'Proxied' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'eu' })).toHaveAttribute('aria-pressed', 'false');
  expect(screen.getByRole('combobox', { name: 'Endpoint' })).toBeInTheDocument();
  expect(screen.getByLabelText('API token')).toHaveAttribute('type', 'password');
  expect(screen.queryByLabelText('Internal path')).not.toBeInTheDocument();
  expect(screen.queryByText('Internal path')).not.toBeInTheDocument();
});

it('shows a stored secret as Stored with Replace, and a non-stored secret as a plain write-only field', () => {
  renderUI(<Harness storedSecrets={['apiToken']} />);
  expect(screen.getByText('Stored')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Replace API token' })).toBeInTheDocument();
});

it('validates required fields on demand', async () => {
  const ref = createRef<SchemaFormHandle>();
  renderUI(<Harness handle={ref} />);
  let ok = true;
  act(() => {
    ok = ref.current!.validate();
  });
  expect(ok).toBe(false);
  expect((await screen.findAllByText(/required/i)).length).toBeGreaterThan(0);
});

it('uses the schema description as a two-sentence tooltip', async () => {
  const { user } = renderUI(<Harness />);
  await user.hover(screen.getAllByRole('button', { name: 'Help' })[0]!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Token with Zone.DNS edit rights. Create it in the dashboard.');
  expect(screen.getByRole('tooltip')).not.toHaveTextContent('Third sentence');
});

// preflight A11 (Critical): every committed provider schema declares draft
// 2020-12; the default @rjsf/validator-ajv8 Ajv instance is draft-07 and
// fails to compile it, so validateForm() always returns false with no
// visible error. This reads the real schema from the repo at test time and
// exercises the fix end to end (SchemaForm -> Ajv2020 -> validateForm()).
const cloudflareSchemaPath = path.resolve(import.meta.dirname, '../../../internal/challenge/schemas/cloudflare.json');
const realCloudflareSchema = (JSON.parse(readFileSync(cloudflareSchemaPath, 'utf-8')) as { schema: RJSFSchema }).schema;

function RealSchemaHarness({ value, handle }: { value: Record<string, unknown>; handle: Ref<SchemaFormHandle> }) {
  const [v, setV] = useState<Record<string, unknown>>(value);
  return <SchemaForm ref={handle} schema={realCloudflareSchema} value={v} onChange={setV} />;
}

it('compiles the real cloudflare.json schema (draft 2020-12) and accepts a valid config', () => {
  const ref = createRef<SchemaFormHandle>();
  renderUI(<RealSchemaHarness value={{ CF_DNS_API_TOKEN: 'token-value' }} handle={ref} />);
  let ok = false;
  act(() => {
    ok = ref.current!.validate();
  });
  expect(ok).toBe(true);
});

it('rejects an invalid config against the real cloudflare.json schema', () => {
  const ref = createRef<SchemaFormHandle>();
  renderUI(<RealSchemaHarness value={{ CF_API_KEY: 123 as unknown as string }} handle={ref} />);
  let ok = true;
  act(() => {
    ok = ref.current!.validate();
  });
  expect(ok).toBe(false);
});
