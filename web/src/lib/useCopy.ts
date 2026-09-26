import { useEffect, useState } from 'react';

export type CopyStatus = 'idle' | 'copied' | 'failed';

/** Copies value to the clipboard; a missing Clipboard API (plain-http LAN
 * deployments) or a refused write shows as `failed`, never an unhandled
 * rejection. The status falls back to idle after 1.5 s. */
export function useCopy(value: string): { status: CopyStatus; copy: () => Promise<void> } {
  const [status, setStatus] = useState<CopyStatus>('idle');
  useEffect(() => {
    if (status === 'idle') return;
    const t = window.setTimeout(() => setStatus('idle'), 1500);
    return () => window.clearTimeout(t);
  }, [status]);
  const copy = async () => {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(value);
      setStatus('copied');
    } catch {
      setStatus('failed');
    }
  };
  return { status, copy };
}
