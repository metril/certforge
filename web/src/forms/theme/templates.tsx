import { createContext, useContext } from 'react';
import { ArrowDown, ArrowUp, CircleAlert, Copy, Plus, X, type LucideIcon } from 'lucide-react';
import { getInputProps, type BaseInputTemplateProps, type FieldTemplateProps, type IconButtonProps, type ObjectFieldTemplateProps, type TemplatesType } from '@rjsf/utils';
import { HelpTip } from '@/components/HelpTip';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';
import { IconButton } from '@/components/IconButton';

// B5: RJSF's own SchemaField consumes a field's `ui:classNames` before it
// ever reaches that field's `uiSchema` prop further down (its comment: "Don't
// pass consumed class names or style to child components") — so a nested
// object field's own ObjectFieldTemplate never sees it, only the FieldTemplate
// instance that wraps that object's label + content. FieldTemplate's own
// `uiSchema` prop (used for `showLabel` below) is still the field's original,
// unstripped uiSchema, so it reads `ui:classNames` there and forwards it
// through this context for the nested ObjectFieldTemplate (Issuance's
// rateLimits two-column grid) to apply to its own properties grid, instead
// of to this label-and-content wrapper.
const ObjectGridClassNames = createContext<string | undefined>(undefined);

function FieldTemplate({ id, label, displayLabel, rawDescription, required, rawErrors, children, hidden, classNames, schema, uiSchema, registry }: FieldTemplateProps) {
  if (hidden) return <div className="hidden">{children}</div>;
  // Booleans render their own label + help inside SwitchField. RJSF forces
  // displayLabel=false whenever a field sets `ui:field` (our `listArray`
  // custom field, uiSchema.ts's buildUiSchema), so a chip-entry list like
  // Agents' Listener names or Authentication's scopes/trustedProxies would
  // otherwise render with no label and no help tip at all. RJSF also forces
  // displayLabel=false for every plain object field (getDisplayLabel.js),
  // which would otherwise hide a nested object's own title/description —
  // Issuance's "Rate limits" heading and its tooltip — so a NESTED object
  // field always shows its heading too; the root object itself (its `id`
  // equals the form's own configured `idPrefix` — `registry.globalFormOptions
  // .idPrefix`, not a hardcoded "root" literal, though every schema-driven
  // form here uses SchemaForm's unconfigured default of "root") is excluded,
  // since its own schema.title (e.g. Issuance's root "Issuance") is meant as
  // this app's tab/heading copy, not a label repeated inside the form body.
  const isObject = schema.type === 'object';
  const isNestedObject = isObject && id !== registry.globalFormOptions.idPrefix;
  const showLabel = (displayLabel || uiSchema?.['ui:field'] === 'listArray' || isNestedObject) && !!label && schema.type !== 'boolean';
  const body = (
    <>
      {showLabel && (
        <div className="flex items-center gap-1.5">
          {isNestedObject ? (
            // A plain heading, not a <Label htmlFor>: a nested object field
            // (e.g. Issuance's "Rate limits") renders several inputs of its
            // own below, not one control this text could label, and "root_
            // rateLimits" isn't the id of anything on the page.
            <span className="text-sm font-medium">{label}</span>
          ) : (
            <Label htmlFor={id}>{label}</Label>
          )}
          {/* "Optional" names a single field's own requiredness; an object
              heading doesn't get one (skipped for every nested object, not
              just when `required` happens to be set — `required` here is
              never meaningful for one of these object fields today). */}
          {!isNestedObject && !required && <span className="text-xs text-ink-muted">Optional</span>}
          {rawDescription && <HelpTip text={rawDescription} />}
        </div>
      )}
      {children}
      {rawErrors && rawErrors.length > 0 && (
        <p role="alert" className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          {rawErrors[0]}
        </p>
      )}
    </>
  );
  if (isObject) {
    const gridClassNames = typeof uiSchema?.['ui:classNames'] === 'string' ? uiSchema['ui:classNames'] : undefined;
    return (
      <ObjectGridClassNames.Provider value={gridClassNames}>
        <div className="grid gap-1.5">{body}</div>
      </ObjectGridClassNames.Provider>
    );
  }
  return <div className={cn('grid gap-1.5', classNames)}>{body}</div>;
}

function ObjectFieldTemplate({ properties }: ObjectFieldTemplateProps) {
  // B5: honours the `ui:classNames` FieldTemplate forwarded above (e.g.
  // Issuance's rateLimits: 'grid gap-3 sm:grid-cols-2') on this template's
  // own properties grid, not on the label-and-content wrapper.
  const gridClassNames = useContext(ObjectGridClassNames);
  return (
    <div className={cn('grid gap-4', gridClassNames)}>
      {properties
        .filter((p) => !p.hidden)
        .map((p) => (
          <div key={p.name}>{p.content}</div>
        ))}
    </div>
  );
}

function BaseInputTemplate(props: BaseInputTemplateProps) {
  const { id, htmlName, value, required, disabled, readonly, autofocus, placeholder, onChange, onChangeOverride, onBlur, onFocus, options, schema, type, rawErrors } = props;
  const inputProps = getInputProps(schema, type, options);
  // `ui:options.mono` (Task 8: vault-kv's path and KV document field names)
  // opts a plain string field into the mono font alongside the formats that
  // already imply a machine value.
  const mono = schema.format === 'uri' || schema.format === 'hostname' || schema.format === 'ipv4' || options.mono === true;
  return (
    <Input
      id={id}
      name={htmlName || id}
      {...inputProps}
      value={value ?? ''}
      required={required}
      disabled={disabled || readonly}
      autoFocus={autofocus}
      placeholder={placeholder}
      aria-invalid={!!rawErrors?.length}
      className={mono ? 'font-mono text-xs' : undefined}
      onChange={onChangeOverride ?? ((e) => onChange(e.target.value === '' ? options.emptyValue : e.target.value))}
      onBlur={(e) => onBlur(id, e.target.value)}
      onFocus={(e) => onFocus(id, e.target.value)}
    />
  );
}

function iconButton(label: string, Icon: LucideIcon) {
  return function IconBtn({ onClick, disabled }: IconButtonProps) {
    return (
      <IconButton type="button" variant="ghost" size="icon" label={label} onClick={onClick} disabled={disabled}>
        <Icon className="size-4" aria-hidden />
      </IconButton>
    );
  };
}

export const templates: Partial<Omit<TemplatesType, 'ButtonTemplates'>> & { ButtonTemplates?: Partial<TemplatesType['ButtonTemplates']> } = {
  FieldTemplate,
  ObjectFieldTemplate,
  BaseInputTemplate,
  DescriptionFieldTemplate: () => null,
  TitleFieldTemplate: () => null,
  ErrorListTemplate: () => null,
  ButtonTemplates: {
    SubmitButton: () => null,
    AddButton: iconButton('Add item', Plus),
    RemoveButton: iconButton('Remove item', X),
    MoveUpButton: iconButton('Move up', ArrowUp),
    MoveDownButton: iconButton('Move down', ArrowDown),
    CopyButton: iconButton('Copy item', Copy),
  },
};
