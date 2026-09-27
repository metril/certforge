import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
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
      <div className={cn('flex items-center justify-between gap-3 rounded-md border border-dashed p-3 text-sm', invalid ? 'border-failed' : 'border-border')}>
        <span className="min-w-0 truncate">
          {value.name} <span className="text-ink-muted">· {fmtBytes(value.size)}</span>
        </span>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={disabled}
          onClick={() => {
            pick(null);
            if (inputRef.current) inputRef.current.value = '';
          }}
        >
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
    pick(e.dataTransfer.files?.[0]);
  }

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-1 rounded-md border border-dashed p-6 text-center text-sm text-ink-muted',
        invalid ? 'border-failed' : 'border-border',
        dragOver && !disabled && 'border-primary bg-primary/5 text-ink',
        !disabled && 'cursor-pointer',
        disabled && 'cursor-not-allowed opacity-60',
      )}
      onClick={() => !disabled && inputRef.current?.click()}
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
