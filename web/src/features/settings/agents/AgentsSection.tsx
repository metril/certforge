import { help } from '@/lib/help';
import { SchemaSection } from '../SchemaSection';
import { AgentCaPanel } from './AgentCaPanel';

// Fix round 1 (review): the Agent URL field needs a caveat the server's own
// schema description doesn't carry — that changing it never reaches an
// agent that already enrolled — so it's added as a per-field uiSchema
// override (SchemaForm's `uiSchemaOverrides`) rather than an inline
// paragraph, keeping this a tooltip like every other field's help.
const agentsUiSchema = (value: Record<string, unknown>) => ({
  agentUrl: { 'ui:description': help['agents.agentUrl'].text },
  requireApproval: { 'ui:description': help['agents.requireApproval'].text },
  // Greyed out while approval is off: no request is ever pending then.
  pendingTtlHours: { 'ui:description': help['agents.pendingTtlHours'].text, 'ui:disabled': value.requireApproval === false },
  // The server's schema has no property order guarantee; Agent URL leads
  // (the field most likely to need editing), then the identity fields
  // callers set once, then the tuning fields.
  'ui:order': ['agentUrl', 'listenerNames', 'tokenTtlHours', 'requireApproval', 'pendingTtlHours', 'agentCertDays', 'heartbeatSeconds', 'offlineAfterSeconds', '*'],
});

export function AgentsSection() {
  return (
    <div className="grid gap-4">
      <SchemaSection section="agents" uiSchemaOverrides={agentsUiSchema} />
      <AgentCaPanel />
    </div>
  );
}
