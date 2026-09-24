import type { ReactNode } from 'react';
import { Button } from '@/components/ui/button';

export function BulkBar({ count, onClear, children }: { count: number; onClear: () => void; children: ReactNode }) {
  if (count === 0) return null;
  return (
    <div role="region" aria-label="Bulk actions" className="fixed inset-x-0 bottom-6 z-40 mx-auto flex w-fit items-center gap-3 rounded-md border border-primary/40 bg-panel px-4 py-2">
      <span className="text-sm font-semibold">{count} selected</span>
      {children}
      <Button variant="ghost" size="sm" onClick={onClear}>
        Clear
      </Button>
    </div>
  );
}
