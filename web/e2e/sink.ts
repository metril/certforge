import { createServer } from 'node:http';

/** One request the sink received. */
export type SinkRequest = { method: string; headers: Record<string, string | string[] | undefined>; body: string };

/**
 * A plain HTTP server the test itself runs, on 0.0.0.0:port, reached by the
 * compose server (inside the container) as
 * `http://${E2E.sinkHost}:${port}/hook` (deploy/compose.test.yaml's
 * `extra_hosts: host.docker.internal:host-gateway` on the certforge
 * service) — the Playwright-side mirror of test/e2e/ops_test.go's own
 * opsWebhookSink. `requests` is a live array the caller reads after the
 * webhook fires; `close` must run even on a failing test (the caller's own
 * `try`/`finally`), same as that Go helper's `t.Cleanup`.
 */
export async function startSink(port: number): Promise<{ requests: SinkRequest[]; close: () => Promise<void> }> {
  const requests: SinkRequest[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method ?? '', headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200);
      res.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', resolve);
  });
  return {
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
