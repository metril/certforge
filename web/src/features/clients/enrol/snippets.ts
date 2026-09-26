export const AGENT_IMAGE = 'ghcr.io/metril/certforge-agent:latest';

// Deviation from the task-2-brief.md literal sample (3a-facts.md wins):
// the shipped 3A agent requires `CF_WRITE_ALLOW` — with it empty every
// deploy fails at once (docs/agent.md "Write allowlist") — so both
// snippets set it to a placeholder directory the operator edits to match
// their layout or deploy target, mirroring agent.md's own examples
// (`docs/agent.md#running-with-docker`). `CF_AGENT_TOKEN_FILE` is
// supported too but optional; these snippets keep the simpler
// `CF_AGENT_TOKEN` form the token panel already shows in full.
const WRITE_DIR = '/etc/certforge/deploy';

/** Plan 3A shared contracts "Enrol snippets"; the token is base64url and
 * dots only, so single quotes are enough. */
export function dockerRunSnippet(token: string): string {
  return [
    'docker run -d --name certforge-agent --restart unless-stopped \\',
    `  -e CF_AGENT_TOKEN='${token}' \\`,
    `  -e CF_WRITE_ALLOW=${WRITE_DIR} \\`,
    '  -v certforge-agent:/data \\',
    `  -v ${WRITE_DIR}:${WRITE_DIR} \\`,
    `  ${AGENT_IMAGE}`,
  ].join('\n');
}

export function composeSnippet(token: string): string {
  return [
    'services:',
    '  certforge-agent:',
    `    image: ${AGENT_IMAGE}`,
    '    restart: unless-stopped',
    '    environment:',
    `      CF_AGENT_TOKEN: '${token}'`,
    `      CF_WRITE_ALLOW: ${WRITE_DIR}`,
    '    volumes:',
    '      - certforge-agent:/data',
    // A named volume is invisible to Traefik on the host; bind-mount the
    // same host directory docker run uses so whatever else reads
    // WRITE_DIR (Traefik's file provider, a bind-mounted target) sees it.
    `      - ${WRITE_DIR}:${WRITE_DIR}`,
    'volumes:',
    '  certforge-agent:',
  ].join('\n');
}
