export const HOUR = 3_600_000;
export const DAY = 86_400_000;

const toMs = (t: string | number) => (typeof t === 'string' ? Date.parse(t) : t);

/** Whole days until t, rounded away from zero, so "5 hours left" reads "in 1 d". */
export function daysUntil(t: string | number, now = Date.now()): number {
  const ms = toMs(t) - now;
  if (ms === 0) return 0;
  return ms > 0 ? Math.ceil(ms / DAY) : -Math.ceil(-ms / DAY);
}

export function relDays(t: string, now = Date.now()): string {
  const d = daysUntil(t, now);
  if (d === 0) return 'today';
  return d > 0 ? `in ${d} d` : `${-d} d ago`;
}

export function fmtDate(t: string): string {
  return new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtDateTime(t: string): string {
  return new Date(t).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Short relative time for activity lists (`just now`, `N min ago`, `N h ago`,
 * `N d ago`) and, for a future `t` (`in N min`, `in N h`, `in N d`) — used for
 * example by the rate-ledger panel's "resets in 2 h". Both directions share
 * the same just-now threshold, so a few seconds of clock skew either way
 * still reads as `just now`. */
export function relTime(t: string, now = Date.now()): string {
  const diff = Date.parse(t) - now;
  const past = diff <= 0;
  const s = Math.abs(diff) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) { const m = Math.floor(s / 60); return past ? `${m} min ago` : `in ${m} min`; }
  if (s < 86_400) { const h = Math.floor(s / 3600); return past ? `${h} h ago` : `in ${h} h`; }
  const d = Math.floor(s / 86_400);
  return past ? `${d} d ago` : `in ${d} d`;
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}
