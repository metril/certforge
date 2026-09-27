// Browser cap: a base64 P12 upload inflates by 4/3, and the server caps the
// JSON body at 1 MiB (global-constraints.md, Deviations).
export const MAX_P12_BYTES = 768 * 1024;
export const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;

/** Reads `file` and resolves with its contents as bare base64 (no `data:` prefix). */
export function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === 'string' ? reader.result : '';
      const comma = result.indexOf(',');
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.onerror = () => reject(reader.error ?? new Error('Could not read file.'));
    reader.readAsDataURL(file);
  });
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB'];

/** Formats a byte count as "1.2 MiB", "32 MiB", "512 B", ... */
export function fmtBytes(n: number): string {
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 ? String(value) : value.toFixed(1).replace(/\.0$/, '');
  return `${digits} ${UNITS[unit]}`;
}
