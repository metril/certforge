import { SchemaSection } from '../SchemaSection';
import { AgentCaPanel } from './AgentCaPanel';

export function AgentsSection() {
  return (
    <div className="grid gap-10">
      <SchemaSection section="agents" />
      <AgentCaPanel />
    </div>
  );
}
