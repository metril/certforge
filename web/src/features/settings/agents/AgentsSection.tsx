import { help } from '@/lib/help';
import { SchemaSection } from '../SchemaSection';
import { AgentCaPanel } from './AgentCaPanel';

// Fix round 1 (review): the Agent URL field needs a caveat the server's own
// schema description doesn't carry — that changing it never reaches an
// agent that already enrolled — so it's added as a per-field uiSchema
// override (SchemaForm's `uiSchemaOverrides`) rather than an inline
// paragraph, keeping this a tooltip like every other field's help.
const AGENTS_UI_SCHEMA = { agentUrl: { 'ui:description': help['agents.agentUrl'].text } };

export function AgentsSection() {
  return (
    <div className="grid gap-10">
      <SchemaSection section="agents" uiSchemaOverrides={AGENTS_UI_SCHEMA} />
      <AgentCaPanel />
    </div>
  );
}
