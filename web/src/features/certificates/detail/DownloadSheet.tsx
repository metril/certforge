import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, Copy, Eye, EyeOff, Lock, RefreshCw, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { downloadVersion, exportVersion, versionsQuery, type Part } from '@/api/queries/certificates';
import type { Certificate, ExportFormat, ExportRequest, P12Encoding } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { help } from '@/lib/help';
import { generatePassword } from '@/lib/password';
import { fmtDate } from '@/lib/time';
import { useCopy } from '@/lib/useCopy';

type Format = 'pem' | 'der' | ExportFormat;
type Props = { orgId: string; cert: Certificate; initialVersionId?: string; canExportKey: boolean; onOpenChange: (open: boolean) => void };

const NEEDS_EXPORT = 'Needs the keys:export permission';

// A 422's title is "Invalid <field>" (mapErr/unprocessable, internal/api) —
// the same shape CertificateWizard's own fieldOfTitle reads; duplicated
// locally since that helper lives in the wizard module and isn't exported.
function fieldOfTitle(title?: string): string | null {
  if (!title) return null;
  return title.replace(/^Invalid\s+/, '').split('.')[0] || null;
}

function passwordError(format: Format, pw: string): string {
  if (pw === '') return 'Enter a password.';
  if (pw.length > 128) return 'At most 128 characters.';
  if (format === 'jks' && pw.length < 6) return 'At least 6 characters.';
  return '';
}

export function DownloadSheet({ orgId, cert, initialVersionId, canExportKey, onOpenChange }: Props) {
  const { data: versions = [], isLoading } = useQuery(versionsQuery(orgId, cert.id));
  const [versionId, setVersionId] = useState(initialVersionId ?? cert.currentVersion?.id);
  const [format, setFormat] = useState<Format>('pem');
  const [parts, setParts] = useState<Part[]>(['fullchain']);
  const [password, setPassword] = useState(() => generatePassword());
  const [own, setOwn] = useState(false);
  const [ownPassword, setOwnPassword] = useState('');
  const [reveal, setReveal] = useState(false);
  const [encoding, setEncoding] = useState<P12Encoding>('modern');
  const [alias, setAlias] = useState('');
  const [serverError, setServerError] = useState<{ field: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const { status: copyStatus, copy } = useCopy(password);

  // Reads hasKey from versionsQuery (not cert.currentVersion), since the
  // sheet can target any historical version, not just the current one.
  const selectedVersion = versions.find((v) => v.id === versionId);
  const hasKey = selectedVersion?.hasKey ?? true;
  const canKey = canExportKey && hasKey;
  const keyHint = !canExportKey ? NEEDS_EXPORT : hasKey ? undefined : help['download.noKey'].text;

  function changeFormat(f: Format) {
    setFormat(f);
    setServerError(null);
    if (f === 'pem') setParts(['fullchain']);
    else if (f === 'der') setParts(['cert']);
  }

  const isKeyBundle = format === 'p12' || format === 'jks';
  const effectivePassword = own ? ownPassword : password;
  const pwError = isKeyBundle ? passwordError(format, effectivePassword) : '';
  const keyBearing = isKeyBundle || parts.includes('key') || parts.includes('combined');
  const passwordFieldError = serverError?.field === 'password' ? serverError.message : own && pwError ? pwError : undefined;
  const aliasFieldError = serverError?.field === 'alias' ? serverError.message : undefined;

  async function run() {
    if (!versionId) return;
    setBusy(true);
    setServerError(null);
    try {
      if (format === 'pem' || format === 'der') {
        await downloadVersion(orgId, cert.id, versionId, { format, parts }, cert.name);
      } else {
        const body: ExportRequest = { format, password: effectivePassword };
        if (format === 'p12') body.encoding = encoding;
        if (format === 'jks' && alias) body.alias = alias;
        await exportVersion(orgId, cert.id, versionId, body, cert.name);
      }
      onOpenChange(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        const field = fieldOfTitle(e.problem.title);
        if (field === 'password' || field === 'alias') {
          setServerError({ field, message: e.problem.detail ?? e.message });
          return;
        }
      }
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const disabled = !versionId || busy || (format === 'pem' || format === 'der' ? parts.length === 0 : !!pwError);
  const label =
    format === 'p12'
      ? 'Download PKCS#12'
      : format === 'jks'
        ? 'Download JKS'
        : parts.length > 1
          ? 'Download ZIP'
          : format === 'der'
            ? 'Download DER'
            : 'Download PEM';

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Download</SheetTitle>
          <SheetDescription className="sr-only">Choose version, format, and parts</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <Field id="dl-version" label="Version">
            <Combobox
              id="dl-version"
              mono
              disabled={isLoading}
              value={versionId}
              onChange={setVersionId}
              options={versions.map((v) => ({
                value: v.id,
                label: `${v.serial}${v.id === cert.currentVersion?.id ? ' (current)' : ''}`,
                hint: `expires ${fmtDate(v.notAfter)}`,
              }))}
              placeholder="Choose version"
              emptyText="No versions"
            />
          </Field>
          <Field id="dl-format" label="Format" help="download.format">
            <SegmentedControl<Format>
              id="dl-format"
              aria-label="Format"
              size="sm"
              value={format}
              onChange={changeFormat}
              options={[
                { value: 'pem', label: 'PEM' },
                { value: 'der', label: 'DER' },
                { value: 'p12', label: 'PKCS#12', disabled: !canKey, hint: canKey ? undefined : keyHint },
                { value: 'jks', label: 'JKS', disabled: !canKey, hint: canKey ? undefined : keyHint },
              ]}
            />
          </Field>
          {(format === 'pem' || format === 'der') && (
            <Field id="dl-parts" label="Parts" help={format === 'pem' ? 'download.parts' : 'download.derParts'}>
              <ChipSet<Part>
                id="dl-parts"
                aria-label="Parts"
                value={parts}
                onChange={setParts}
                options={
                  format === 'pem'
                    ? [
                        { value: 'cert', label: 'cert' },
                        { value: 'chain', label: 'chain' },
                        { value: 'fullchain', label: 'fullchain' },
                        { value: 'key', label: 'key', disabled: !canKey, hint: canKey ? undefined : keyHint },
                        { value: 'combined', label: 'combined', disabled: !canKey, hint: canKey ? undefined : keyHint },
                      ]
                    : [
                        { value: 'cert', label: 'cert' },
                        { value: 'chain', label: 'chain' },
                        { value: 'key', label: 'key', disabled: !canKey, hint: canKey ? undefined : keyHint },
                      ]
                }
              />
            </Field>
          )}
          {isKeyBundle && (
            <>
              <Field id="dl-password" label="Password" help="download.password" error={passwordFieldError}>
                {own ? (
                  <div className="flex items-center gap-2">
                    <Input
                      id="dl-password"
                      type={reveal ? 'text' : 'password'}
                      className="font-mono text-xs"
                      autoComplete="new-password"
                      value={ownPassword}
                      onChange={(e) => {
                        setOwnPassword(e.target.value);
                        setServerError(null);
                      }}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      aria-label={reveal ? 'Hide password' : 'Show password'}
                      onClick={() => setReveal((r) => !r)}
                    >
                      {reveal ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Input id="dl-password" type="text" readOnly aria-label="Generated password" className="font-mono text-xs" value={password} />
                    <Button type="button" variant="ghost" size="icon" aria-label="Copy password" onClick={() => void copy()}>
                      {copyStatus === 'copied' && <Check className="size-4 text-valid" aria-hidden />}
                      {copyStatus === 'failed' && <TriangleAlert className="size-4 text-failed" aria-hidden />}
                      {copyStatus === 'idle' && <Copy className="size-4" aria-hidden />}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      aria-label="Regenerate password"
                      onClick={() => setPassword(generatePassword())}
                    >
                      <RefreshCw className="size-4" aria-hidden />
                    </Button>
                  </div>
                )}
              </Field>
              <SwitchField
                id="dl-own-password"
                label="Use my own password"
                help="download.ownPassword"
                checked={own}
                onCheckedChange={(v) => {
                  setOwn(v);
                  setServerError(null);
                }}
                onText="Own"
                offText="Generated"
              />
              {format === 'p12' && (
                <Field id="dl-encoding" label="Encoding" help="download.encoding">
                  <SegmentedControl<P12Encoding>
                    id="dl-encoding"
                    aria-label="Encoding"
                    value={encoding}
                    onChange={setEncoding}
                    options={[
                      { value: 'modern', label: 'Modern' },
                      { value: 'legacy', label: 'Legacy' },
                    ]}
                  />
                </Field>
              )}
              {format === 'jks' && (
                <Field id="dl-alias" label="Alias" help="download.alias" optional error={aliasFieldError}>
                  <Input
                    id="dl-alias"
                    placeholder="tomcat"
                    value={alias}
                    onChange={(e) => {
                      setAlias(e.target.value);
                      setServerError(null);
                    }}
                  />
                </Field>
              )}
            </>
          )}
          {keyBearing && (
            <div className="flex items-center gap-1.5 text-sm text-ink-muted">
              <Lock className="size-4" aria-hidden />
              Recorded in the audit log
              <HelpTip id="download.key" />
            </div>
          )}
          <Button disabled={disabled} onClick={() => void run()}>
            {label}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}
