import { Link } from '@tanstack/react-router';
import type { Certificate } from '@/api/types';
import { CertValidity } from '@/components/ValidityBar';

// Below `md` this is a card row (name, then validity and the right-hand
// note stacked); at `md` and up it's a three-column line, per the phone
// layout carry-in (queue and renewals render as card rows below md).
export function CertRow({ cert, org, right }: { cert: Certificate; org: string; right: React.ReactNode }) {
  return (
    <li className="grid gap-1 border-b border-border py-2 text-sm md:h-9 md:grid-cols-[minmax(0,1fr)_128px_auto] md:items-center md:gap-4 md:py-0">
      <Link to="/o/$org/certificates/$id/$tab" params={{ org, id: cert.id, tab: 'overview' }} className="truncate font-semibold hover:underline">
        {cert.name}
      </Link>
      <CertValidity cert={cert} />
      <span className="whitespace-nowrap text-ink-muted">{right}</span>
    </li>
  );
}
