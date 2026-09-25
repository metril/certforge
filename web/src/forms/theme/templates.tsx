import { ArrowDown, ArrowUp, CircleAlert, Copy, Plus, X, type LucideIcon } from 'lucide-react';
import { getInputProps, type BaseInputTemplateProps, type FieldTemplateProps, type IconButtonProps, type ObjectFieldTemplateProps, type TemplatesType } from '@rjsf/utils';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';

function FieldTemplate({ id, label, displayLabel, rawDescription, required, rawErrors, children, hidden, classNames, schema }: FieldTemplateProps) {
  if (hidden) return <div className="hidden">{children}</div>;
  // Booleans render their own label + help inside SwitchField.
  const showLabel = displayLabel && !!label && schema.type !== 'boolean';
  return (
    <div className={cn('grid gap-1.5', classNames)}>
      {showLabel && (
        <div className="flex items-center gap-1.5">
          <Label htmlFor={id}>{label}</Label>
          {!required && <span className="text-xs text-ink-muted">Optional</span>}
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
    </div>
  );
}

function ObjectFieldTemplate({ properties }: ObjectFieldTemplateProps) {
  return (
    <div className="grid gap-4">
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
  const mono = schema.format === 'uri' || schema.format === 'hostname' || schema.format === 'ipv4';
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
      <Button type="button" variant="ghost" size="icon" aria-label={label} onClick={onClick} disabled={disabled}>
        <Icon className="size-4" aria-hidden />
      </Button>
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
