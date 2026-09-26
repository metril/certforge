export const TAB_LINK = 'inline-flex h-9 shrink-0 items-center whitespace-nowrap border-b-2 border-transparent px-1 text-sm text-ink-muted hover:text-ink';
export const TAB_ACTIVE = { className: 'border-primary! font-semibold text-ink!', 'aria-current': 'page' as const };

/** A long tab label with a short form below `md`. Both spans are
 * aria-hidden; the link carries the full label as its aria-label. */
export function TabLabel({ full, short }: { full: string; short: string }) {
  return (
    <>
      <span aria-hidden="true" className="hidden md:inline">
        {full}
      </span>
      <span aria-hidden="true" className="md:hidden">
        {short}
      </span>
    </>
  );
}
