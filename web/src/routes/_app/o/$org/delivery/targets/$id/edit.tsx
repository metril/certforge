import { createFileRoute } from '@tanstack/react-router';
import { targetLoader } from '@/features/delivery/targetLoader';
import { EditTargetPage } from '@/features/delivery/TargetPages';

export const Route = createFileRoute('/_app/o/$org/delivery/targets/$id/edit')({
  loader: (ctx) => targetLoader(ctx),
  component: function EditTargetRoute() {
    const { id } = Route.useParams();
    return <EditTargetPage id={id} />;
  },
});
