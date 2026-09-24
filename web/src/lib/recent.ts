const KEY = 'cf-recent-providers';

export function readRecent(): string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KEY) ?? '[]');
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function pushRecent(code: string): void {
  try {
    localStorage.setItem(KEY, JSON.stringify([code, ...readRecent().filter((c) => c !== code)].slice(0, 5)));
  } catch {
    // Storage blocked (private window, quota, disabled): recents are a per-viewer convenience only.
  }
}
