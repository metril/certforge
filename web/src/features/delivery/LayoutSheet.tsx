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
import { emptyFile, hasErrors, keyReadableByOthers, OUTPUT_PARTS, validateFiles } from './layoutFiles';

const MAX_FILES = 20;

type Props = { orgId: string; layout?: Layout; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function LayoutSheet({ orgId, layout, readOnly, onOpenChange }: Props) {
  const save = useSaveLayout(orgId);
  const [name, setName] = useState(layout?.name ?? '');
  const [files, setFiles] = useState<OutputFile[]>(layout?.files ?? [emptyFile()]);
  const [showErrors, setShowErrors] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const errors = validateFiles(files);
  const title = layout ? (readOnly ? layout.name : `Edit ${layout.name}`) : 'New layout';

  const setFile = (i: number, patch: Partial<OutputFile>) => setFiles((fs) => fs.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  const move = (i: number, d: -1 | 1) =>
    setFiles((fs) => {
      const next = [...fs];
      [next[i], next[i + d]] = [next[i + d]!, next[i]!];
      return next;
    });

  const submit = async () => {
    setShowErrors(true);
    setFormError(null);
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    if (!nameOk || hasErrors(errors)) return;
    try {
      await save.mutateAsync({ id: layout?.id, body: { name: name.trim(), files: files.map((f) => ({ ...f, path: f.path.trim() })) } });
      onOpenChange(false);
    } catch (e) {
      const msg = errorMessage(e);
      // Only a name conflict ("A file layout named ... already exists" — the
      // server's detail names the layout) belongs under Name; a 409 on a
      // path collision across a client's grants names a client/certificate
      // pair, not "name", and reads better as a page-level alert than
      // silently attached to the wrong field (3a-facts.md, mirroring
      // Task 7's TargetSheet).
      if (e instanceof ApiError && e.status === 409 && /name/i.test(msg)) setNameError(msg);
      else setFormError(msg);
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
            {files.map((f, i) => {
              const e = showErrors ? errors[i]! : {};
              const n = i + 1;
              const fid = `layout-file-${i}`;
              return (
                <li key={i} aria-label={`File ${n}`} className="grid gap-3 rounded-md border border-border p-3">
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
                        <Button variant="ghost" size="icon-sm" className="size-9" aria-label={`Move file ${n} down`} disabled={i === files.length - 1} onClick={() => move(i, 1)}>
                          <ArrowDown className="size-4" aria-hidden />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="size-9"
                          aria-label={`Remove file ${n}`}
                          disabled={files.length === 1}
                          onClick={() => setFiles((fs) => fs.filter((_, j) => j !== i))}
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
            <Button variant="outline" size="sm" className="w-fit" disabled={files.length >= MAX_FILES} onClick={() => setFiles((fs) => [...fs, emptyFile()])}>
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
