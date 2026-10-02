import { useRef } from 'react';

/** True once `value` differs (by JSON.stringify) from its first-render snapshot.
 * Sheets that mount per open take the snapshot when they open. */
export function useDirty(value: unknown): boolean {
  const initial = useRef<string>(undefined as unknown as string);
  const current = JSON.stringify(value);
  if (initial.current === undefined) initial.current = current;
  return current !== initial.current;
}
