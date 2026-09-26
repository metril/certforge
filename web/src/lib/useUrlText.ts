import { useEffect, useRef, useState } from 'react';

/** A text box bound to a URL search param with a 250 ms debounce. An
 * external URL change (saved view, chip removal, back/forward) wins over
 * stale typing; same algorithm as CertificatesPage's search box. */
export function useUrlText(urlValue: string | undefined, push: (v: string | undefined) => void): [string, (v: string) => void] {
  const [text, setText] = useState(urlValue ?? '');
  const pushed = useRef(urlValue ?? '');
  useEffect(() => {
    const url = urlValue ?? '';
    if (url !== pushed.current) {
      pushed.current = url;
      if (url !== text) setText(url);
      return;
    }
    if (text === url) return;
    const t = window.setTimeout(() => {
      pushed.current = text;
      push(text || undefined);
    }, 250);
    return () => window.clearTimeout(t);
    // push is a fresh closure every render; text and urlValue drive this.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, urlValue]);
  return [text, setText];
}
