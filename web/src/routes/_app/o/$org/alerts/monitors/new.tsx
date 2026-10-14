import { createFileRoute } from '@tanstack/react-router';
import { NewMonitorPage } from '@/features/alerts/MonitorPages';

export const Route = createFileRoute('/_app/o/$org/alerts/monitors/new')({ staticData: { ownHeader: true }, component: NewMonitorPage });
