/** Preset check intervals offered by the monitor sheet (UI conventions "Formats"). */
export const INTERVALS: { value: number; label: string }[] = [
  { value: 300, label: '5 m' },
  { value: 900, label: '15 m' },
  { value: 3600, label: '1 h' },
  { value: 21_600, label: '6 h' },
  { value: 86_400, label: '24 h' },
];

/** A preset's own label, else minutes (e.g. "90 m") or whole hours. */
export function fmtInterval(seconds: number): string {
  const preset = INTERVALS.find((i) => i.value === seconds);
  if (preset) return preset.label;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${Math.round(seconds / 60)} m`;
}

/** First 16 hex characters of a fingerprint plus an ellipsis; the full value
 * belongs in a CopyField (UI conventions "Formats"). */
export function shortFp(fp: string): string {
  return fp.length > 16 ? `${fp.slice(0, 16)}…` : fp;
}
