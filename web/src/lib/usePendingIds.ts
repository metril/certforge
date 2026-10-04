import { useCallback, useState } from 'react';

/** Ids with a request in flight. A shared mutation's `variables` only holds
 * the latest trigger, so per-row pending state is tracked here instead. */
export function usePendingIds() {
  const [ids, setIds] = useState<ReadonlySet<string>>(new Set());
  const isPending = useCallback((id: string) => ids.has(id), [ids]);
  /** Marks `id` pending until `p` settles; the returned promise never rejects. */
  const track = useCallback((id: string, p: Promise<unknown>) => {
    setIds((s) => new Set(s).add(id));
    return p.then(
      () => undefined,
      () => undefined,
    ).finally(() =>
      setIds((s) => {
        const n = new Set(s);
        n.delete(id);
        return n;
      }),
    );
  }, []);
  return { isPending, track };
}
