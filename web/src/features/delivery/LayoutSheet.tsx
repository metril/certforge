import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, CircleAlert, Eye, EyeOff, Plus, TriangleAlert, X } from 'lucide-react';
import { allCertificatesQuery } from '@/api/queries/certificates';
import { useSaveLayout } from '@/api/queries/delivery';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { UNCHANGED } from '@/api/types';
import type { Layout, OutputFile, OutputFormat, OutputPart, P12Encoding } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import type { ComboOption } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { MultiCombobox } from '@/components/MultiCombobox';
import { SecretInput } from '@/components/SecretInput';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { generatePassword } from '@/lib/password';
import {
  emptyFile,
  hasErrors,
  keyReadableByOthers,
  layoutErrors,
  OUTPUT_FORMATS,
  OUTPUT_PARTS,
  pathPlaceholder,
  validateFiles,
  withFormat,
  type FileErrors,
} from './layoutFiles';

const MAX_FILES = 20;
const MAX_EXTRAS = 10;

// A stable per-row id (independent of array position) so Move up/down keeps
// keyboard focus attached to the file that moved, not to the slot it left.
let nextRowId = 0;
type Row = { id: string; file: OutputFile };
const makeRow = (file: OutputFile = emptyFile()): Row => ({ id: `row-${nextRowId++}`, file });

// The 422 the server sends for a bad file field names it as "files[i].field"
// in the problem's title (internal/api/issuance_common.go's unprocessable),
// e.g. "Invalid files[0].mode" — map that back onto the row, else fall
// through to the page alert. A layout-level field (password,
// extraCertificateIds) has no "files[i]." prefix and is handled separately.
const FIELD_422 = /^Invalid files\[(\d+)\]\.(path|parts|mode|owner|group|encoding|alias)$/;
const LAYOUT_FIELDS = new Set(['password', 'extraCertificateIds']);

type Props = { orgId: string; layout?: Layout; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function LayoutSheet({ orgId, layout, readOnly, onOpenChange }: Props) {
  const save = useSaveLayout(orgId);
  const { data: allCerts = [] } = useQuery(allCertificatesQuery(orgId));
  const [name, setName] = useState(layout?.name ?? '');
  const [rows, setRows] = useState<Row[]>(() => (layout?.files ?? [emptyFile()]).map(makeRow));
  const [extraCertificateIds, setExtraCertificateIds] = useState<string[]>(layout?.extraCertificateIds ?? []);
  // The stored-password (SecretInput) branch is fixed at mount by whether
  // this layout already has a password: switching modes mid-edit would
  // require re-deriving passwordSet from files the operator is still
  // editing, which the server's own `passwordSet` flag never does either.
  const [hasStoredPassword] = useState(layout?.passwordSet ?? false);
  const [storedPassword, setStoredPassword] = useState<string | undefined>(undefined);
  const [newPassword, setNewPassword] = useState(() => generatePassword());
  const [reveal, setReveal] = useState(false);
  const [showErrors, setShowErrors] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [serverError, setServerError] = useState<{ i: number; field: keyof FileErrors; msg: string } | null>(null);
  const [layoutServerError, setLayoutServerError] = useState<{ field: 'password' | 'extraCertificateIds'; msg: string } | null>(null);
  const files = rows.map((r) => r.file);
  const errors = validateFiles(files);
  const title = layout ? (readOnly ? layout.name : `Edit ${layout.name}`) : 'New layout';

  const anyKeystoreFile = files.some((f) => f.format === 'p12' || f.format === 'jks');
  const showPassword = anyKeystoreFile || (layout?.passwordSet ?? false);
  const passwordValue = hasStoredPassword ? storedPassword : newPassword;
  const lErrors = layoutErrors({ files, password: passwordValue, passwordSet: layout?.passwordSet ?? false, extraCertificateIds });
  const passwordError = layoutServerError?.field === 'password' ? layoutServerError.msg : showErrors ? lErrors.password : undefined;
  const extrasError = layoutServerError?.field === 'extraCertificateIds' ? layoutServerError.msg : showErrors ? lErrors.extraCertificateIds : undefined;

  const certOptions: ComboOption[] = allCerts
    .filter((c) => c.currentVersion)
    .map((c) => {
      const atCap = extraCertificateIds.length >= MAX_EXTRAS && !extraCertificateIds.includes(c.id);
      return { value: c.id, label: c.name, disabled: atCap, hint: atCap ? 'Up to 10' : undefined };
    });

  const setFile = (i: number, patch: Partial<OutputFile>) => {
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, file: { ...r.file, ...patch } } : r)));
    if (serverError?.i === i) setServerError(null);
  };
  const setFormat = (i: number, format: OutputFormat) => {
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, file: withFormat(r.file, format) } : r)));
    if (serverError?.i === i) setServerError(null);
  };
  const move = (i: number, d: -1 | 1) =>
    setRows((rs) => {
      const next = [...rs];
      [next[i], next[i + d]] = [next[i + d]!, next[i]!];
      return next;
    });

  const submit = async () => {
    setShowErrors(true);
    setFormError(null);
    setServerError(null);
    setLayoutServerError(null);
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    if (!nameOk || hasErrors(errors) || Object.keys(lErrors).length > 0) return;
    const passwordBody = hasStoredPassword ? (storedPassword ?? UNCHANGED) : newPassword;
    try {
      await save.mutateAsync({
        id: layout?.id,
        body: {
          name: name.trim(),
          files: files.map((f) => ({ ...f, path: f.path.trim() })),
          extraCertificateIds,
          ...(showPassword ? { password: passwordBody } : {}),
        },
      });
      onOpenChange(false);
    } catch (e) {
      const msg = errorMessage(e);
      if (e instanceof ApiError) {
        // Only a name conflict ("A layout named ... exists in this org" —
        // the server's own wording) belongs under Name; a 409 on a path
        // collision across a client's grants names a client/certificate
        // pair, not a layout name, and reads better as a page-level alert
        // than silently attached to the wrong field (3a-facts.md, mirroring
        // Task 7's TargetSheet).
        if (e.status === 409 && /^A layout named/i.test(msg)) {
          setNameError(msg);
          return;
        }
        const field = FIELD_422.exec(e.problem.title ?? '');
        if (field) {
          setServerError({ i: Number(field[1]), field: field[2] as keyof FileErrors, msg });
          return;
        }
        const topField = fieldOfTitle(e.problem.title);
        if (topField && LAYOUT_FIELDS.has(topField)) {
          setLayoutServerError({ field: topField as 'password' | 'extraCertificateIds', msg });
          return;
        }
      }
      setFormError(msg);
    }
  };

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription className="sr-only">Files the agent writes for each grant using this layout</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
          <Field id="layout-name" label="Name" error={nameError}>
            <Input
              id="layout-name"
              value={name}
              placeholder="nginx"
              autoComplete="off"
              disabled={readOnly}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
            />
          </Field>
          <ol aria-label="Files" className="grid gap-3">
            {rows.map((row, i) => {
              const e: FileErrors = { ...(showErrors ? errors[i] : {}), ...(serverError?.i === i ? { [serverError.field]: serverError.msg } : {}) };
              const f = row.file;
              const n = i + 1;
              const fid = `layout-file-${i}`;
              return (
                <li key={row.id} aria-label={`File ${n}`} className="grid gap-3 rounded-md border border-border p-3">
                  <div className="flex items-start gap-1">
                    <Field id={`${fid}-path`} label="Path" help="layout.path" error={e.path} className="min-w-0 flex-1">
                      <Input
                        id={`${fid}-path`}
                        className="font-mono text-xs"
                        placeholder={pathPlaceholder(f.format)}
                        value={f.path}
                        disabled={readOnly}
                        onChange={(ev) => setFile(i, { path: ev.target.value })}
                      />
                    </Field>
                    {!readOnly && (
                      <div className="flex pt-6">
                        <Button variant="ghost" size="icon-sm" className="size-9" aria-label={`Move file ${n} up`} disabled={i === 0} onClick={() => move(i, -1)}>
                          <ArrowUp className="size-4" aria-hidden />
                        </Button>
                        <Button variant="ghost" size="icon-sm" className="size-9" aria-label={`Move file ${n} down`} disabled={i === rows.length - 1} onClick={() => move(i, 1)}>
                          <ArrowDown className="size-4" aria-hidden />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="size-9"
                          aria-label={`Remove file ${n}`}
                          disabled={rows.length === 1}
                          onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
                        >
                          <X className="size-4" aria-hidden />
                        </Button>
                      </div>
                    )}
                  </div>
                  <Field id={`${fid}-format`} label="Format" help="layout.format">
                    <SegmentedControl<OutputFormat>
                      id={`${fid}-format`}
                      aria-label={`Format of file ${n}`}
                      size="sm"
                      value={f.format}
                      onChange={(fmt) => setFormat(i, fmt)}
                      options={OUTPUT_FORMATS.map((o) => ({ ...o, disabled: readOnly }))}
                    />
                  </Field>
                  {f.format === 'pem' && (
                    <Field id={`${fid}-parts`} label="Parts" help="layout.parts" error={e.parts}>
                      <ChipSet<OutputPart>
                        id={`${fid}-parts`}
                        aria-label={`Parts of file ${n}`}
                        value={f.parts}
                        onChange={(parts) => setFile(i, { parts })}
                        options={OUTPUT_PARTS.map((p) => ({
                          value: p,
                          label: p,
                          disabled: readOnly || (p === 'extra' && extraCertificateIds.length === 0),
                          hint: p === 'extra' && extraCertificateIds.length === 0 ? 'Add extra certificates first' : undefined,
                        }))}
                      />
                    </Field>
                  )}
                  {f.format === 'der' && (
                    <Field id={`${fid}-parts`} label="Parts" help="layout.derPart" error={e.parts}>
                      <SegmentedControl<OutputPart>
                        id={`${fid}-parts`}
                        aria-label={`Parts of file ${n}`}
                        value={f.parts[0] === 'key' ? 'key' : 'cert'}
                        onChange={(p) => setFile(i, { parts: [p] })}
                        options={[
                          { value: 'cert', label: 'Certificate', disabled: readOnly },
                          { value: 'key', label: 'Key', disabled: readOnly },
                        ]}
                      />
                    </Field>
                  )}
                  {f.format === 'p12' && (
                    <Field id={`${fid}-encoding`} label="Encoding" help="download.encoding" error={e.encoding}>
                      <SegmentedControl<P12Encoding>
                        id={`${fid}-encoding`}
                        aria-label={`Encoding of file ${n}`}
                        value={f.encoding ?? 'modern'}
                        onChange={(v) => setFile(i, { encoding: v })}
                        options={[
                          { value: 'modern', label: 'Modern', disabled: readOnly },
                          { value: 'legacy', label: 'Legacy', disabled: readOnly },
                        ]}
                      />
                    </Field>
                  )}
                  {f.format === 'jks' && (
                    <Field id={`${fid}-alias`} label="Alias" help="download.alias" optional error={e.alias}>
                      <Input
                        id={`${fid}-alias`}
                        className="font-mono text-xs"
                        placeholder="example.com"
                        value={f.alias ?? ''}
                        disabled={readOnly}
                        onChange={(ev) => setFile(i, { alias: ev.target.value })}
                      />
                    </Field>
                  )}
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <Field id={`${fid}-owner`} label="Owner" help="layout.owner" optional error={e.owner}>
                      <Input id={`${fid}-owner`} placeholder="root" value={f.owner} disabled={readOnly} onChange={(ev) => setFile(i, { owner: ev.target.value })} />
                    </Field>
                    <Field id={`${fid}-group`} label="Group" help="layout.group" optional error={e.group}>
                      <Input id={`${fid}-group`} placeholder="www-data" value={f.group} disabled={readOnly} onChange={(ev) => setFile(i, { group: ev.target.value })} />
                    </Field>
                    <Field id={`${fid}-mode`} label="Mode" help="layout.mode" error={e.mode}>
                      <Input
                        id={`${fid}-mode`}
                        className="font-mono text-xs"
                        inputMode="numeric"
                        placeholder="0640"
                        value={f.mode}
                        disabled={readOnly}
                        onChange={(ev) => setFile(i, { mode: ev.target.value })}
                      />
                    </Field>
                  </div>
                  {keyReadableByOthers(f) && (
                    <p className="flex items-center gap-1.5 text-xs">
                      <TriangleAlert className="size-3.5 text-expiring" aria-hidden />
                      Key readable by every user
                      <HelpTip id="layout.keyMode" />
                    </p>
                  )}
                </li>
              );
            })}
          </ol>
          {!readOnly && (
            <Button variant="outline" size="sm" className="w-fit" disabled={rows.length >= MAX_FILES} onClick={() => setRows((rs) => [...rs, makeRow()])}>
              <Plus className="size-4" aria-hidden />
              Add file
            </Button>
          )}
          {showPassword && (
            <Field id="layout-password" label="Password" help="layout.password" error={passwordError}>
              {hasStoredPassword ? (
                <SecretInput
                  id="layout-password"
                  label="Password"
                  value={storedPassword}
                  onChange={setStoredPassword}
                  stored={layout!.passwordSet}
                  disabled={readOnly}
                  removable={!anyKeystoreFile}
                />
              ) : (
                <div className="flex items-center gap-2">
                  <Input
                    id="layout-password"
                    type={reveal ? 'text' : 'password'}
                    className="font-mono text-xs"
                    autoComplete="new-password"
                    value={newPassword}
                    disabled={readOnly}
                    onChange={(ev) => setNewPassword(ev.target.value)}
                  />
                  {!readOnly && (
                    <>
                      <Button type="button" variant="ghost" size="icon" aria-label={reveal ? 'Hide password' : 'Show password'} onClick={() => setReveal((r) => !r)}>
                        {reveal ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
                      </Button>
                      <Button type="button" variant="ghost" size="sm" onClick={() => setNewPassword(generatePassword())}>
                        Generate
                      </Button>
                    </>
                  )}
                </div>
              )}
            </Field>
          )}
          <Field id="layout-extras" label="Extra certificates" help="layout.extraCerts" error={extrasError}>
            <MultiCombobox
              id="layout-extras"
              aria-label="Extra certificates"
              value={extraCertificateIds}
              onChange={setExtraCertificateIds}
              options={certOptions}
              placeholder="Add certificates"
              emptyText="No certificate matches."
              disabled={readOnly}
            />
          </Field>
          {formError && (
            <p role="alert" className="flex items-center gap-1.5 text-sm">
              <CircleAlert className="size-4 text-failed" aria-hidden />
              {formError}
            </p>
          )}
        </div>
        <SheetFooter className="flex-row justify-end gap-2">
          {readOnly ? (
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button disabled={save.isPending} onClick={() => void submit()}>
                Save
              </Button>
            </>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
