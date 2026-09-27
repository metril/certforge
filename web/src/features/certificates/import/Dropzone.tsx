import { useRef, useState, type ChangeEvent, type DragEvent, type MouseEvent } from 'react';
import { Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { fmtBytes } from '@/lib/files';
import { cn } from '@/lib/utils';

type Props = {
  id?: string;
  accept: string;
  /** Only tints the border; the message itself is the caller's `Field` error (generic across every caller's own size copy). */
  maxBytes?: number;
  value: File | null;
  onChange: (file: File | null) => void;
  error?: string;
  disabled?: boolean;
  'aria-label'?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean;
};

// Fix round 1 (review, Minor): a dropped file used to bypass `accept`
// entirely (only a click-opened native picker filters by extension). Only
// extension matching is needed here — every caller passes a plain
// comma-separated extension list (".zip,.tar.gz,.tgz", ".p12,.pfx"), never a
// MIME type or wildcard.
function matchesAccept(fileName: string, accept: string): boolean {
  const exts = accept
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (exts.length === 0) return true;
  const lower = fileName.toLowerCase();
  return exts.some((ext) => lower.endsWith(ext));
}

/** A styled native file input, generic across Upload's PKCS#12 picker and
 * Import's archive picker: drag-and-drop over the same hidden
 * `<input type="file">` a click opens, so it stays a real file input rather
 * than a custom widget standing in for one. `id`/`aria-*` are forwarded onto
 * that input so a wrapping `Field`'s label and error association keep
 * working exactly as they did for a plain `Input`. */
export function Dropzone({ id, accept, maxBytes, value, onChange, error, disabled, ...aria }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const invalid = !!error || (!!maxBytes && !!value && value.size > maxBytes);
  // Fix round 1 (review, Important): the sr-only input has no visible focus
  // ring of its own; a keyboard user tabbing to it (both branches mount the
  // real input, visually hidden) needs the wrapper itself to show focus,
  // matching input.tsx's own focus-visible ring tokens.
  const focusRing = 'focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50';

  function pick(file: File | undefined | null) {
    onChange(file ?? null);
  }

  const input = (
    <input
      ref={inputRef}
      id={id}
      type="file"
      accept={accept}
      disabled={disabled}
      className="sr-only"
      onChange={(e: ChangeEvent<HTMLInputElement>) => pick(e.target.files?.[0])}
      {...aria}
    />
  );

  if (value) {
    return (
      <div
        className={cn(
          'flex items-center justify-between gap-3 rounded-md border border-dashed p-3 text-sm',
          invalid ? 'border-failed' : 'border-border',
          focusRing,
        )}
      >
        <span className="min-w-0 truncate">
          {value.name} <span className="text-ink-muted">· {fmtBytes(value.size)}</span>
        </span>
        {/* Fix round 1 (review, Minor): this used to only clear the value —
            a button labelled "Replace" (the brief's own exact copy for the
            archive picker) needs to actually offer a replacement, not just
            remove the current file. Reopening the same picker without
            first clearing `value` means a cancelled dialog leaves the
            current file in place, which "Replace" implies and "Remove"
            would not have. */}
        <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={() => inputRef.current?.click()}>
          Replace
        </Button>
        {input}
      </div>
    );
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    if (disabled) return;
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file && matchesAccept(file.name, accept)) pick(file);
  }

  // Fix round 1 (review, Minor): the wrapper's own onClick re-opens the
  // picker on any click inside it, including a click that lands directly on
  // the (visually hidden but still real, still clickable) input — which
  // already opens its own dialog natively and then bubbles here, stacking a
  // second `.click()` on top. Ignoring a click whose target is the input
  // itself keeps exactly one dialog open per interaction.
  function onWrapperClick(e: MouseEvent<HTMLDivElement>) {
    if (disabled || e.target === inputRef.current) return;
    inputRef.current?.click();
  }

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-1 rounded-md border border-dashed p-6 text-center text-sm text-ink-muted',
        invalid ? 'border-failed' : 'border-border',
        dragOver && !disabled && 'border-primary bg-primary/5 text-ink',
        !disabled && 'cursor-pointer',
        disabled && 'cursor-not-allowed opacity-60',
        focusRing,
      )}
      onClick={onWrapperClick}
      onDragOver={(e) => {
        if (disabled) return;
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
    >
      <Upload className="size-5" aria-hidden />
      <span>Drop a file here, or click to choose</span>
      {input}
    </div>
  );
}
