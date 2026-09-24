export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 font-semibold text-ink">
      <svg viewBox="0 0 32 32" className="size-6" aria-hidden>
        <rect x="3" y="13" width="26" height="6" fill="var(--cf-primary)" opacity=".3" />
        <rect x="18" y="13" width="11" height="6" fill="var(--cf-primary)" />
        <rect x="16.5" y="8" width="2.5" height="16" fill="var(--cf-ink)" />
      </svg>
      {!compact && <span className="text-base">CertForge</span>}
    </span>
  );
}
