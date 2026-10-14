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
  /** Interactive lead-in for the meta line (e.g. a grants popover); clicks do not reach the row. */
  lead?: ReactNode;
};

/** Two-line table cell: primary text plus a muted meta line. Both lines
 * truncate (the meta line with a tooltip of the full text), so it fits a
 * `table-fixed` column; put sticky/width classes on the TableCell itself. */
export function PrimaryCell({ primary, link, meta = [], metaTitle, lead }: PrimaryCellProps) {
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
      {lead && (
        <div className="flex min-w-0 items-baseline gap-1 text-xs text-ink-muted">
          <span className="shrink-0" onClick={(e) => e.stopPropagation()}>
            {lead}
          </span>
          {text && <span aria-hidden>·</span>}
          {text && <MetaText text={text} title={metaTitle} />}
        </div>
      )}
      {!lead && text && <MetaText text={text} title={metaTitle} />}
    </div>
  );
}

function MetaText({ text, title }: { text: string; title?: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="block min-w-0 truncate text-xs text-ink-muted">
          {text}
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-96 break-words text-xs">
        {title ?? text}
      </TooltipContent>
    </Tooltip>
  );
}
