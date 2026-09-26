import { useState } from 'react';
import { ArrowDown, ArrowUp, CircleAlert, Plus, TriangleAlert, X } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { useSaveLayout } from '@/api/queries/delivery';
import type { Layout, OutputFile, OutputPart } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { emptyFile, hasErrors, keyReadableByOthers, OUTPUT_PARTS, validateFiles, type FileErrors } from './layoutFiles';

const MAX_FILES = 20;

// A stable per-row id (independent of array position) so Move up/down keeps
// keyboard focus attached to the file that moved, not to the slot it left.
let nextRowId = 0;
type Row = { id: string; file: OutputFile };
const makeRow = (file: OutputFile = emptyFile()): Row => ({ id: `row-${nextRowId++}`, file });

// The 422 the server sends for a bad file field names it as "files[i].field"
// in the problem's title (internal/api/issuance_common.go's unprocessable),
// e.g. "Invalid files[0].mode" — map that back onto the row, else fall
// through to the page alert.
const FIELD_422 = /^Invalid files\[(\d+)\]\.(path|parts|mode|owner|group)$/;

type Props = { orgId: string; layout?: Layout; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function LayoutSheet({ orgId, layout, readOnly, onOpenChange }: Props) {
  const save = useSaveLayout(orgId);
  const [name, setName] = useState(layout?.name ?? '');
  const [rows, setRows] = useState<Row[]>(() => (layout?.files ?? [emptyFile()]).map(makeRow));
  const [showErrors, setShowErrors] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [serverError, setServerError] = useState<{ i: number; field: keyof FileErrors; msg: string } | null>(null);
  const files = rows.map((r) => r.file);
  const errors = validateFiles(files);
  const title = layout ? (readOnly ? layout.name : `Edit ${layout.name}`) : 'New layout';

  const setFile = (i: number, patch: Partial<OutputFile>) => {
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, file: { ...r.file, ...patch } } : r)));
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
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    if (!nameOk || hasErrors(errors)) return;
    try {
      await save.mutateAsync({ id: layout?.id, body: { name: name.trim(), files: files.map((f) => ({ ...f, path: f.path.trim() })) } });
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
                        placeholder="/etc/ssl/example.com/fullchain.pem"
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
                  <Field id={`${fid}-parts`} label="Parts" help="layout.parts" error={e.parts}>
                    <div className="flex flex-wrap items-center gap-2">
                      <ChipSet<OutputPart>
                        id={`${fid}-parts`}
                        aria-label={`Parts of file ${n}`}
                        value={f.parts}
                        onChange={(parts) => setFile(i, { parts })}
                        options={OUTPUT_PARTS.map((p) => ({ value: p, label: p, disabled: readOnly }))}
                      />
                      <span className="inline-flex h-7 items-center gap-1 rounded-sm border border-border bg-subtle px-2 text-xs">
                        PEM <HelpTip id="layout.format" />
                      </span>
                    </div>
                  </Field>
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
