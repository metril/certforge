import type { ReactNode } from 'react';

export function PageHeader({ title, actions, children }: { title: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div className="grid min-w-0 gap-1">
        <h1 className="text-xl font-semibold">{title}</h1>
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
