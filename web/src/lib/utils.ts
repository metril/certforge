import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// A cmdk `filter` that matches only against an item's `keywords`, never its
// raw `value` — cmdk's default filter scores the `value` string itself too,
// which is a problem once `value` is an internal identifier rather than
// user-facing text (a namespaced key, a uuid, ...): typing a substring of
// that identifier would match every item that shares it, regardless of
// what's actually shown or searchable (fix round 1: ProviderPicker's old
// `section:code`/`cred:uuid` values made "all" or "cred" match everything).
export function keywordFilter(_value: string, search: string, keywords?: string[]): number {
  const haystack = (keywords ?? []).join(' ').toLowerCase();
  return haystack.includes(search.trim().toLowerCase()) ? 1 : 0;
}
