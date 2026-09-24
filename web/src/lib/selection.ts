import { useCallback, useEffect, useRef, useState } from 'react';

export function nextSelection(
  prev: ReadonlySet<string>,
  ids: readonly string[],
  clicked: string,
  opts: { shift: boolean; anchor: string | null },
): { selected: Set<string>; anchor: string } {
  const next = new Set(prev);
  if (opts.shift && opts.anchor && ids.includes(opts.anchor)) {
    const a = ids.indexOf(opts.anchor);
    const b = ids.indexOf(clicked);
    const [lo, hi] = a < b ? [a, b] : [b, a];
    for (const id of ids.slice(lo, hi + 1)) next.add(id);
    return { selected: next, anchor: opts.anchor };
  }
  if (next.has(clicked)) next.delete(clicked);
  else next.add(clicked);
  return { selected: next, anchor: clicked };
}

export function useRowSelection(ids: string[]) {
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const anchor = useRef<string | null>(null);
  const key = ids.join('|');

  useEffect(() => {
    // Drop selections that scrolled out of the result set.
    setSelected((prev) => {
      const keep = new Set([...prev].filter((id) => ids.includes(id)));
      return keep.size === prev.size ? prev : keep;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const onRowClick = useCallback(
    (id: string, e: { shiftKey: boolean }) => {
      setSelected((prev) => {
        const r = nextSelection(prev, ids, id, { shift: e.shiftKey, anchor: anchor.current });
        anchor.current = r.anchor;
        return r.selected;
      });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [key],
  );

  const clear = useCallback(() => setSelected(new Set()), []);
  return { selected, onRowClick, clear };
}
