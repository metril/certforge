import { createFileRoute } from '@tanstack/react-router';
import { EditMonitorPage } from '@/features/alerts/MonitorPages';

export const Route = createFileRoute('/_app/o/$org/alerts/monitors/$id/edit')({
  staticData: { ownHeader: true },
  component: function EditMonitorRoute() {
    const { id } = Route.useParams();
    return <EditMonitorPage id={id} />;
  },
});
