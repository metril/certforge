import { expect, it } from 'vitest';
import { composeSnippet, dockerRunSnippet } from './snippets';

const token = 'cf1.aHR0cHM6Ly9jZi5sYW46ODQ0Mw.ab12.s3cret';

// Deviation from task-2-brief.md's literal sample (3a-facts.md wins): the
// shipped 3A agent requires CF_WRITE_ALLOW, so both snippets set it.

it('renders the docker run line with the token and a required CF_WRITE_ALLOW', () => {
  const out = dockerRunSnippet(token);
  expect(out).toContain(`-e CF_AGENT_TOKEN='${token}'`);
  expect(out).toContain('-e CF_WRITE_ALLOW=/etc/certforge/deploy');
  expect(out).toContain('-v certforge-agent:/data');
  expect(out).toContain('ghcr.io/metril/certforge-agent:latest');
});

it('renders a compose file with the token, a named data volume and a bind-mounted CF_WRITE_ALLOW dir', () => {
  const out = composeSnippet(token);
  expect(out).toContain(`CF_AGENT_TOKEN: '${token}'`);
  expect(out).toContain('CF_WRITE_ALLOW: /etc/certforge/deploy');
  expect(out).toContain('image: ghcr.io/metril/certforge-agent:latest');
  expect(out).toContain('- certforge-agent:/data');
  // Bind-mounted (not a named volume), matching docker run's own mount and
  // readable by whatever else (Traefik, ...) shares the host directory.
  expect(out).toContain('- /etc/certforge/deploy:/etc/certforge/deploy');
  expect(out).not.toContain('certforge-deploy');
  expect(out.trim().endsWith('volumes:\n  certforge-agent:')).toBe(true);
});
