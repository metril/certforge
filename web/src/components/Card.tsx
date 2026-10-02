import { createContext, forwardRef, useContext, type ComponentPropsWithoutRef, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

const CardContext = createContext(false);

/** True inside a `Card`: nested tables and FormSections drop their own frame. */
export function useInCard(): boolean {
  return useContext(CardContext);
}

/** Framed surface: `bg-panel` + border on the `bg-surface` canvas. No shadow, no borderless variant. */
export const Card = forwardRef<HTMLDivElement, ComponentPropsWithoutRef<'div'>>(function Card({ className, ...props }, ref) {
  return (
    <CardContext.Provider value>
      <div ref={ref} data-slot="card" className={cn('rounded-md border border-border bg-panel', className)} {...props} />
    </CardContext.Provider>
  );
});

export function CardHeader({ title, titleId, actions, className, children }: { title?: ReactNode; titleId?: string; actions?: ReactNode; className?: string; children?: ReactNode }) {
  return (
    <div data-slot="card-header" className={cn('flex items-center justify-between gap-2 border-b border-border px-4 py-3', className)}>
      {title != null && <h2 id={titleId} className="text-sm font-semibold">{title}</h2>}
      {children}
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, ...props }: ComponentPropsWithoutRef<'div'>) {
  return <div data-slot="card-body" className={cn('p-4', className)} {...props} />;
}
