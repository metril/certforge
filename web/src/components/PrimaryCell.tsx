import type { ReactNode } from 'react';
import { Link, type LinkProps } from '@tanstack/react-router';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

export type PrimaryCellProps = {
  /** First line, semibold. */
  primary: ReactNode;
  /** Make the primary text a router link. */
  link?: Pick<LinkProps, 'to' | 'params' | 'search'>;
  /** Short parts for the muted second line, joined by " · "; empty/falsy parts are dropped. */
  meta?: (string | null | undefined | false)[];
  /** Tooltip content for the meta line when it should say more than the line itself (e.g. full paths). */
  metaTitle?: ReactNode;
};

/** Two-line table cell: primary text plus a muted meta line. Both lines
 * truncate (the meta line with a tooltip of the full text), so it fits a
 * `table-fixed` column; put sticky/width classes on the TableCell itself. */
export function PrimaryCell({ primary, link, meta = [], metaTitle }: PrimaryCellProps) {
  const parts = meta.filter((m): m is string => !!m);
  const text = parts.join(' · ');
  const head = link ? (
    <Link {...(link as LinkProps)} onClick={(e) => e.stopPropagation()} className="block truncate font-semibold hover:underline">
      {primary}
    </Link>
  ) : (
    <span className="block truncate font-semibold">{primary}</span>
  );
  return (
    <div className="min-w-0">
      {head}
      {text && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} className="block truncate text-xs text-ink-muted">
              {text}
            </span>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-96 break-words text-xs">
            {metaTitle ?? text}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}
