import { createFileRoute } from '@tanstack/react-router';
import { EditLayoutPage } from '@/features/delivery/LayoutPages';

export const Route = createFileRoute('/_app/o/$org/delivery/layouts/$id/edit')({
  staticData: { ownHeader: true },
  component: function EditLayoutRoute() {
    const { id } = Route.useParams();
    return <EditLayoutPage id={id} />;
  },
});
