import type { ReactNode } from 'react';

/** One sentence plus one button. */
export function EmptyState({ message, children }: { message: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 border border-dashed border-border px-6 py-10">
      <p className="text-base">{message}</p>
      {children}
    </div>
  );
}
