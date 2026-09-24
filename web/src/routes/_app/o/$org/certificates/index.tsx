import { createFileRoute } from '@tanstack/react-router';
import { CertificatesPage } from '@/features/certificates/list/CertificatesPage';
import { certListSearch } from '@/features/certificates/list/search';

export const Route = createFileRoute('/_app/o/$org/certificates/')({
  validateSearch: certListSearch,
  component: CertificatesPage,
});
