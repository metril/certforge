import { enumOptionsIndexForValue, enumOptionsValueForIndex, type RegistryWidgetsType, type WidgetProps } from '@rjsf/utils';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, ListRestart, LoaderCircle } from 'lucide-react';
import type { AdcsProbeTemplate } from '@/api/types';
import { orgsQuery } from '@/api/queries/orgs';
import { CaBundleInput, type CaBundleScope } from '@/components/CaBundleInput';
import { ChipSet } from '@/components/ChipSet';
import { Combobox, type ComboOption } from '@/components/Combobox';
import { IconButton } from '@/components/IconButton';
import { PermissionTip } from '@/components/PermissionTip';
import { SecretInput } from '@/components/SecretInput';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Textarea } from '@/components/ui/textarea';

// `ui:options.permission`/`ui:options.allowed` (Task 8: vault-kv's includeKey,
// gated on keys:export) disables the switch, behind a PermissionTip, only
// while turning it ON would need the permission the caller lacks — a stored
// `true` stays visible and interactable so the operator can still turn it
// off; the server enforces the permission either way.
function SwitchWidget({ id, value, onChange, disabled, readonly, label, schema, options }: WidgetProps) {
  const permission = typeof options.permission === 'string' ? options.permission : undefined;
  const gated = permission !== undefined && options.allowed !== true && value !== true;
  // getUiOptions strips a field's own `ui:description` into options.description
  // (batch 4 review: a caller-supplied tooltip, e.g. target.includeKey, was
  // otherwise unreachable here — FieldTemplate's own rawDescription/HelpTip
  // never renders for a boolean field, only this widget's own helpText).
  const control = (
    <SwitchField
      id={id}
      label={label || schema.title || id}
      helpText={typeof options.description === 'string' ? options.description : schema.description}
      checked={value === true}
      onCheckedChange={(v) => onChange(v)}
      disabled={disabled || readonly || gated}
      onText={typeof options.onText === 'string' ? options.onText : 'On'}
      offText={typeof options.offText === 'string' ? options.offText : 'Off'}
    />
  );
  if (!gated) return control;
  return (
    <PermissionTip allowed={false} action={permission}>
      {control}
    </PermissionTip>
  );
}

// Handles `enum` (single choice: SegmentedControl <=5 options, Combobox
// otherwise) and `array` of `enum` (multiple: ChipSet) — the widget RJSF
// picks by default for a plain enum/array-of-enum field with no explicit
// ui:widget, so this single override covers both spec rules (theme mapping).
function SelectWidget(props: WidgetProps) {
  const { id, value, onChange, options, disabled, readonly, multiple, label } = props;
  const enumOptions = options.enumOptions ?? [];
  const off = disabled || readonly;
  if (multiple) {
    const selected = (enumOptionsIndexForValue(value, enumOptions, true) as string[] | undefined) ?? [];
    return (
      <ChipSet
        id={id}
        aria-label={label}
        value={selected}
        onChange={(idx) => onChange(idx.map((i) => enumOptionsValueForIndex(i, enumOptions, options.emptyValue)))}
        options={enumOptions.map((o, i) => ({ value: String(i), label: o.label, disabled: off }))}
      />
    );
  }
  const current = enumOptionsIndexForValue(value, enumOptions, false) as string | undefined;
  const chooseByIndex = (i: string) => onChange(enumOptionsValueForIndex(i, enumOptions, options.emptyValue));
  if (enumOptions.length <= 5) {
    return (
      <SegmentedControl
        id={id}
        aria-label={label}
        value={current ?? ''}
        onChange={chooseByIndex}
        options={enumOptions.map((o, i) => ({ value: String(i), label: o.label, disabled: off }))}
      />
    );
  }
  return (
    <Combobox
      id={id}
      aria-label={label}
      value={current}
      onChange={(i) => (i === undefined ? onChange(options.emptyValue) : chooseByIndex(i))}
      clearable={!props.required}
      options={enumOptions.map((o, i) => ({ value: String(i), label: o.label }))}
      placeholder="Choose"
      emptyText="No match"
      disabled={off}
    />
  );
}

function TextareaWidget({ id, value, onChange, disabled, readonly, placeholder, options, rawErrors }: WidgetProps) {
  return (
    <Textarea
      id={id}
      rows={typeof options.rows === 'number' ? options.rows : 5}
      className="font-mono text-xs"
      value={value ?? ''}
      placeholder={placeholder}
      disabled={disabled || readonly}
      aria-invalid={!!rawErrors?.length}
      onChange={(e) => onChange(e.target.value === '' ? options.emptyValue : e.target.value)}
    />
  );
}

function SecretWidget({ id, value, onChange, options, label, placeholder, disabled, readonly, name, registry }: WidgetProps) {
  const ctx = registry.formContext as { onRevealSecret?: (field: string) => Promise<string>; revealDisabledReason?: string } | undefined;
  const onRevealSecret = ctx?.onRevealSecret;
  const fieldName = name || id;
  const canReveal = options.stored === true && !!onRevealSecret;
  return (
    <SecretInput
      id={id}
      label={label}
      value={value as string | undefined}
      onChange={onChange}
      stored={options.stored === true}
      placeholder={placeholder}
      disabled={disabled || readonly}
      onReveal={canReveal ? () => onRevealSecret(fieldName) : undefined}
      revealDisabledReason={canReveal ? ctx?.revealDisabledReason : undefined}
    />
  );
}

// `ui:widget: 'orgSelect'` (Authentication's defaultOrgId): picks one of the
// existing organizations; the stored value is the org id. Clearable, since an
// empty value means "grant nothing automatically".
function OrgSelectWidget({ id, value, onChange, disabled, readonly, label }: WidgetProps) {
  const orgs = useQuery(orgsQuery);
  return (
    <Combobox
      id={id}
      aria-label={label}
      value={value || undefined}
      onChange={(v) => onChange(v ?? '')}
      clearable
      options={(orgs.data ?? []).map((o) => ({ value: o.id, label: o.name, hint: o.slug, keywords: [o.slug] }))}
      placeholder="No default organization"
      emptyText="No match"
      disabled={disabled || readonly}
    />
  );
}

/** formContext.adcsTemplates, set by the AD CS body (CaKindBody). */
export type AdcsTemplateContext = {
  /** Undefined until a probe has read the policy. */
  templates?: AdcsProbeTemplate[];
  /** Why each template cannot be picked, or null when it can. */
  reasonOf: (t: AdcsProbeTemplate) => string | null;
  loading: boolean;
  error?: string;
  onLoad: () => void;
  /** Why Load is disabled (missing settings or permission), if it is. */
  loadBlocked?: string;
  loadTip: string;
};

// `ui:widget: 'adcsTemplate'`: a searchable select over the templates a
// probe read, with unusable ones disabled behind a tooltip reason; free text
// (the plain input) until templates load or when the probe fails.
function AdcsTemplateWidget(props: WidgetProps) {
  const { id, value, onChange, disabled, readonly, label, registry } = props;
  const ctx = (registry.formContext as { adcsTemplates?: AdcsTemplateContext } | undefined)?.adcsTemplates;
  const Base = registry.templates.BaseInputTemplate;
  const templates = ctx?.templates;
  const current = typeof value === 'string' ? value : '';
  let control = <Base {...props} />;
  if (ctx && templates && templates.length > 0) {
    const options: ComboOption[] = templates.map((t) => {
      const reason = ctx.reasonOf(t);
      return { value: t.name, label: t.name, disabled: !!reason, hint: reason ?? `${t.minKeySize}-bit min`, keywords: t.oid ? [t.oid] : [] };
    });
    if (current && !templates.some((t) => t.name === current)) {
      options.unshift({ value: current, label: current, disabled: true, hint: 'Not published by the policy.' });
    }
    control = (
      <Combobox
        id={id}
        aria-label={label}
        mono
        value={current || undefined}
        onChange={(v) => onChange(v ?? '')}
        options={options}
        placeholder="Pick a template"
        emptyText="No template matches."
        disabled={disabled || readonly}
      />
    );
  }
  return (
    <div className="grid gap-1.5">
      <div className="flex items-center gap-1">
        <div className="min-w-0 flex-1">{control}</div>
        {ctx && (
          <IconButton
            type="button"
            variant="outline"
            size="icon"
            className="shrink-0"
            label="Load templates"
            tip={ctx.loadBlocked ?? ctx.loadTip}
            disabled={!!ctx.loadBlocked || ctx.loading || disabled || readonly}
            onClick={ctx.onLoad}
          >
            {ctx.loading ? <LoaderCircle className="size-4 animate-spin" aria-hidden /> : <ListRestart className="size-4" aria-hidden />}
          </IconButton>
        )}
      </div>
      {ctx?.error && (
        <p role="alert" className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          {ctx.error}
        </p>
      )}
    </div>
  );
}

// `ui:widget: 'caBundle'` (every `format: pem-bundle` field, uiSchema.ts):
// formContext.caBundle (caBundleScope) enables Fetch and From saved CA, and
// `ui:options.urlKey` names the sibling field whose value prefills Fetch's
// server (SchemaForm puts the live form data on formContext.formData).
function CaBundleWidget({ id, value, onChange, disabled, readonly, placeholder, options, rawErrors, label, registry }: WidgetProps) {
  const ctx = registry.formContext as { caBundle?: CaBundleScope; formData?: Record<string, unknown> } | undefined;
  const urlKey = typeof options.urlKey === 'string' ? options.urlKey : undefined;
  const url = urlKey ? ctx?.formData?.[urlKey] : undefined;
  return (
    <CaBundleInput
      id={id}
      label={label}
      value={typeof value === 'string' ? value : ''}
      onChange={(v) => onChange(v === '' ? options.emptyValue : v)}
      placeholder={placeholder || undefined}
      disabled={disabled || readonly}
      invalid={!!rawErrors?.length}
      url={typeof url === 'string' ? url : undefined}
      scope={ctx?.caBundle}
    />
  );
}

export const widgets: RegistryWidgetsType = {
  adcsTemplate: AdcsTemplateWidget,
  caBundle: CaBundleWidget,
  orgSelect: OrgSelectWidget,
  CheckboxWidget: SwitchWidget,
  CheckboxesWidget: (p: WidgetProps) => <SelectWidget {...p} multiple />,
  RadioWidget: (p: WidgetProps) => <SelectWidget {...p} multiple={false} />,
  SelectWidget,
  TextareaWidget,
  secret: SecretWidget,
};
