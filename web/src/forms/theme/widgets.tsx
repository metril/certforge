import { enumOptionsIndexForValue, enumOptionsValueForIndex, type RegistryWidgetsType, type WidgetProps } from '@rjsf/utils';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { SecretInput } from '@/components/SecretInput';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Textarea } from '@/components/ui/textarea';

function SwitchWidget({ id, value, onChange, disabled, readonly, label, schema, options }: WidgetProps) {
  return (
    <SwitchField
      id={id}
      label={label || schema.title || id}
      helpText={schema.description}
      checked={value === true}
      onCheckedChange={(v) => onChange(v)}
      disabled={disabled || readonly}
      onText={typeof options.onText === 'string' ? options.onText : 'On'}
      offText={typeof options.offText === 'string' ? options.offText : 'Off'}
    />
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

function SecretWidget({ id, value, onChange, options, label, placeholder }: WidgetProps) {
  return <SecretInput id={id} label={label} value={value as string | undefined} onChange={onChange} stored={options.stored === true} placeholder={placeholder} />;
}

export const widgets: RegistryWidgetsType = {
  CheckboxWidget: SwitchWidget,
  CheckboxesWidget: (p: WidgetProps) => <SelectWidget {...p} multiple />,
  RadioWidget: (p: WidgetProps) => <SelectWidget {...p} multiple={false} />,
  SelectWidget,
  TextareaWidget,
  secret: SecretWidget,
};
