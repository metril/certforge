import type { FieldProps, RegistryFieldsType } from '@rjsf/utils';
import { ListInput } from '@/components/ListInput';
import { HeadersField } from '@/features/alerts/HeadersField';

// A plain array-of-string field (no `enum`, so SelectWidget's ChipSet path
// doesn't apply — e.g. authentication's `scopes` and `trustedProxies`) maps
// to the existing chip-entry ListInput rather than RJSF's default per-item
// add/remove rows (uiSchema.ts routes it here via `ui:field: 'listArray'`).
function ListArrayField({ fieldPathId, formData, onChange, schema, uiSchema, disabled, readonly }: FieldProps) {
  const placeholder = typeof uiSchema?.['ui:placeholder'] === 'string' ? uiSchema['ui:placeholder'] : undefined;
  return (
    <ListInput
      // FieldTemplate's <Label htmlFor={id}> uses this same fieldPathId.$id
      // (SchemaField passes it through as the `id` prop to FieldTemplate),
      // so the two must match for the label to target this input.
      id={fieldPathId.$id}
      aria-label={typeof schema.title === 'string' ? schema.title : undefined}
      value={Array.isArray(formData) ? (formData as string[]) : []}
      // Fix round 1 (Critical): an empty path means "replace the root" in
      // RJSF 6.10 (Form.onChange merges at fieldPathId's OWN path, not at
      // root) — passing [] here silently replaced the whole form's data
      // with just this array. fieldPathId.path is this field's own path
      // relative to its parent object, which is what onChange expects.
      onChange={(v) => onChange(v, fieldPathId.path)}
      placeholder={placeholder}
      disabled={disabled || readonly}
    />
  );
}

export const fields: RegistryFieldsType = {
  listArray: ListArrayField,
  headers: HeadersField,
};
