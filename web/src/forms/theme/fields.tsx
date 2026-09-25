import type { FieldProps, RegistryFieldsType } from '@rjsf/utils';
import { ListInput } from '@/components/ListInput';

// A plain array-of-string field (no `enum`, so SelectWidget's ChipSet path
// doesn't apply — e.g. authentication's `scopes` and `trustedProxies`) maps
// to the existing chip-entry ListInput rather than RJSF's default per-item
// add/remove rows (uiSchema.ts routes it here via `ui:field: 'listArray'`).
function ListArrayField({ id, formData, onChange, schema, uiSchema, disabled, readonly }: FieldProps) {
  const placeholder = typeof uiSchema?.['ui:placeholder'] === 'string' ? uiSchema['ui:placeholder'] : undefined;
  return (
    <ListInput
      id={id}
      aria-label={typeof schema.title === 'string' ? schema.title : undefined}
      value={Array.isArray(formData) ? (formData as string[]) : []}
      onChange={(v) => onChange(v, [])}
      placeholder={placeholder}
      disabled={disabled || readonly}
    />
  );
}

export const fields: RegistryFieldsType = {
  listArray: ListArrayField,
};
