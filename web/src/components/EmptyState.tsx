import type { ReactNode } from 'react';
import { Card, useInCard } from '@/components/Card';

/** One sentence plus one button. Framed in a Card on the canvas; inside a Card it keeps only a dashed outline. */
export function EmptyState({ message, children }: { message: string; children?: ReactNode }) {
  const inCard = useInCard();
  const cls = 'flex flex-col items-start gap-3 border-dashed px-6 py-10';
  const body = (
    <>
      <p className="text-base">{message}</p>
      {children}
    </>
  );
  return inCard ? <div className={`${cls} rounded-md border border-border`}>{body}</div> : <Card className={cls}>{body}</Card>;
}
