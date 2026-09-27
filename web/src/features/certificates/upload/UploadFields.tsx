import { Field } from '@/components/Field';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { fmtBytes } from '@/lib/files';
import { p12TooLarge, type UploadValue } from './uploadBody';

export type UploadFieldErrors = Partial<Record<'certificatePem' | 'privateKeyPem' | 'pkcs12Base64' | 'password', string>>;

type Props = {
  value: UploadValue;
  onChange: (value: UploadValue) => void;
  errors?: UploadFieldErrors;
  disabled?: boolean;
};

/** The certificate-material half of Upload (Task 5) and Task 7's
 * version-upload sheet: format, then either PEM text areas or a PKCS#12
 * file plus password. Name (Upload only) lives in the caller. */
export function UploadFields({ value, onChange, errors = {}, disabled }: Props) {
  const set = <K extends keyof UploadValue>(key: K, next: UploadValue[K]) => onChange({ ...value, [key]: next });
  const tooLarge = value.format === 'p12' && p12TooLarge(value.file);
  const fileError = errors.pkcs12Base64 ?? (tooLarge ? 'Larger than 768 KiB.' : undefined);

  return (
    <div className="grid gap-5">
      <Field id="upload-format" label="Format">
        <SegmentedControl
          id="upload-format"
          aria-label="Format"
          value={value.format}
          onChange={(v) => set('format', v)}
          options={[
            { value: 'pem', label: 'PEM' },
            { value: 'p12', label: 'PKCS#12' },
          ]}
        />
      </Field>
      {value.format === 'pem' ? (
        <>
          <Field id="upload-cert" label="Certificate" help="upload.certificate" error={errors.certificatePem}>
            <Textarea
              id="upload-cert"
              rows={8}
              className="font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE-----"
              disabled={disabled}
              value={value.certificatePem}
              onChange={(e) => set('certificatePem', e.target.value)}
            />
          </Field>
          <Field id="upload-key" label="Private key" help="upload.key" optional error={errors.privateKeyPem}>
            <Textarea
              id="upload-key"
              rows={6}
              className="font-mono text-xs"
              placeholder="-----BEGIN PRIVATE KEY-----"
              disabled={disabled}
              value={value.privateKeyPem}
              onChange={(e) => set('privateKeyPem', e.target.value)}
            />
          </Field>
        </>
      ) : (
        <>
          <Field id="upload-file" label="File" help="upload.pkcs12" error={fileError}>
            {value.file ? (
              <div className="flex items-center justify-between gap-3 rounded-md border border-dashed border-border p-3 text-sm">
                <span className="min-w-0 truncate">
                  {value.file.name} <span className="text-ink-muted">· {fmtBytes(value.file.size)}</span>
                </span>
                <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={() => set('file', null)}>
                  Remove
                </Button>
              </div>
            ) : (
              <Input
                id="upload-file"
                type="file"
                accept=".p12,.pfx"
                disabled={disabled}
                className="cursor-pointer border-dashed"
                onChange={(e) => set('file', e.target.files?.[0] ?? null)}
              />
            )}
          </Field>
          <Field id="upload-password" label="Password" help="upload.password" error={errors.password}>
            <Input
              id="upload-password"
              type="password"
              autoComplete="new-password"
              className="font-mono text-xs"
              disabled={disabled}
              value={value.password}
              onChange={(e) => set('password', e.target.value)}
            />
          </Field>
        </>
      )}
    </div>
  );
}
