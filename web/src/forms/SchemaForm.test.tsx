import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createRef, useState, type Ref } from 'react';
import { act, screen, within } from '@testing-library/react';
import type { RJSFSchema } from '@rjsf/utils';
import { expect, it, vi } from 'vitest';
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

function Harness({ storedSecrets, handle, readonly }: { storedSecrets?: string[]; handle?: Ref<SchemaFormHandle>; readonly?: boolean }) {
  const [v, setV] = useState<Record<string, unknown>>(storedSecrets ? withSecretSentinels(schema, {}, storedSecrets) : {});
  return <SchemaForm ref={handle} schema={schema} value={v} onChange={setV} storedSecrets={storedSecrets} readonly={readonly} />;
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

it('readonly disables the secret widget: no Replace button and no editable input for a stored secret', () => {
  renderUI(<Harness storedSecrets={['apiToken']} readonly />);
  expect(screen.getByText('Stored')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Replace API token' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('API token')).not.toBeInTheDocument();
});

it('readonly shows "Not set" for a non-stored secret, with no input', () => {
  renderUI(<Harness readonly />);
  expect(screen.getByText('Not set')).toBeInTheDocument();
  expect(screen.queryByLabelText('API token')).not.toBeInTheDocument();
});

it('strips serverPath fields from the value it hands back, even if the caller seeded one (an older credential)', async () => {
  const onChange = vi.fn();
  function StaleHarness() {
    const [v, setV] = useState<Record<string, unknown>>({ internalPath: 'stale-value', ttl: 1 });
    return (
      <SchemaForm
        schema={schema}
        value={v}
        onChange={(next) => {
          onChange(next);
          setV(next);
        }}
      />
    );
  }
  const { user } = renderUI(<StaleHarness />);
  await user.clear(screen.getByLabelText('TTL'));
  await user.type(screen.getByLabelText('TTL'), '5');
  expect(onChange).toHaveBeenCalled();
  const last = onChange.mock.calls.at(-1)![0] as Record<string, unknown>;
  expect(last).not.toHaveProperty('internalPath');
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

// validator-fix: replacing @rjsf/validator-ajv8 with the @cfworker/json-schema
// based validator (./validator.ts) must keep every field's own error message
// rendered under that same field, for each keyword the app's real schemas
// use (required, pattern, enum, minimum, format).
const validationSchema = {
  type: 'object',
  required: ['name'],
  properties: {
    name: { type: 'string', title: 'Name' },
    code: { type: 'string', title: 'Code', pattern: '^[A-Z]{3}$' },
    mode: { type: 'string', title: 'Mode', enum: ['a', 'b'] },
    count: { type: 'integer', title: 'Count', minimum: 5 },
    site: { type: 'string', title: 'Site', format: 'uri' },
  },
} as RJSFSchema;

function ValidationHarness({ value, handle }: { value: Record<string, unknown>; handle: Ref<SchemaFormHandle> }) {
  const [v, setV] = useState<Record<string, unknown>>(value);
  return <SchemaForm ref={handle} schema={validationSchema} value={v} onChange={setV} />;
}

it('renders required, pattern, enum, minimum and format errors under their own fields', () => {
  const ref = createRef<SchemaFormHandle>();
  renderUI(<ValidationHarness value={{ code: 'abc', mode: 'z', count: 1, site: 'not a uri' }} handle={ref} />);
  let ok = true;
  act(() => {
    ok = ref.current!.validate();
  });
  expect(ok).toBe(false);

  const errorNear = (el: HTMLElement) => within(el.parentElement!).queryByRole('alert')?.textContent ?? '';

  expect(errorNear(screen.getByLabelText('Name'))).toMatch(/required property "name"/i);
  expect(errorNear(screen.getByLabelText('Code'))).toMatch(/pattern/i);
  expect(errorNear(screen.getByRole('radiogroup', { name: 'Mode' }))).toMatch(/does not match any of/i);
  expect(errorNear(screen.getByLabelText('Count'))).toMatch(/less than/i);
  expect(errorNear(screen.getByLabelText('Site'))).toMatch(/format "uri"/i);
});

// oneOf still has to resolve to the branch matching the current formData
// (RJSF's getFirstMatchingOption calls validator.isValid() per branch).
const oneOfSchema = {
  type: 'object',
  oneOf: [
    { properties: { method: { type: 'string', const: 'email' }, email: { type: 'string', title: 'Email address' } }, required: ['method', 'email'] },
    { properties: { method: { type: 'string', const: 'phone' }, phone: { type: 'string', title: 'Phone number' } }, required: ['method', 'phone'] },
  ],
} as RJSFSchema;

function OneOfHarness({ value }: { value: Record<string, unknown> }) {
  const [v, setV] = useState<Record<string, unknown>>(value);
  return <SchemaForm schema={oneOfSchema} value={v} onChange={setV} />;
}

it('resolves a oneOf schema to the branch matching the current formData', () => {
  renderUI(<OneOfHarness value={{ method: 'phone', phone: '555' }} />);
  expect(screen.getByLabelText('Phone number')).toBeInTheDocument();
  expect(screen.queryByLabelText('Email address')).not.toBeInTheDocument();
});
