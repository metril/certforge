#!/usr/bin/env node
// Fix round 1 (review, Important #4): an automated guard that the main
// entry chunk (and anything it modulepreloads, i.e. everything loaded
// eagerly on first paint) never re-absorbs tldts — the actual cause of
// this task's >500 kB main-chunk warning (see CHANGELOG "Changed": the
// settings route's `beforeLoad` sharing a module with its heavy component
// forced tldts into the eager bundle regardless of how any lazy route was
// written). A route-level regression (a new `beforeLoad`/constant sharing a
// module with a component that reaches `lib/names.ts`) would silently
// reintroduce this; this script fails the build instead of relying on
// someone noticing chunk sizes in `vite build` output.
//
// tldts embeds the public suffix list; the ACE/punycode prefix `xn--` and
// the literal `publicsuffix` are its fingerprints (the actual code around
// them gets renamed by minification, these string/data literals do not).
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.resolve(here, '..', 'dist');
const indexHtml = path.join(distDir, 'index.html');

if (!existsSync(indexHtml)) {
  console.log('check-chunks: dist/index.html not found, skipping (run `npm run build` first).');
  process.exit(0);
}

const html = readFileSync(indexHtml, 'utf8');

/** Every file the browser loads eagerly on first paint: the entry module
 * script(s) plus every `<link rel="modulepreload">` Vite emitted for the
 * synchronous import graph. Lazy route chunks (dynamic `import()`, e.g. the
 * certificate wizard and the settings page) are deliberately NOT
 * modulepreloaded from index.html, so they're out of scope here by design. */
function eagerAssetPaths(document) {
  const paths = [];
  for (const m of document.matchAll(/<script[^>]+type="module"[^>]+src="([^"]+)"/g)) paths.push(m[1]);
  for (const m of document.matchAll(/<link[^>]+rel="modulepreload"[^>]+href="([^"]+)"/g)) paths.push(m[1]);
  return paths;
}

const FINGERPRINTS = ['xn--', 'publicsuffix'];

const assets = eagerAssetPaths(html);
if (assets.length === 0) {
  console.error('check-chunks: found no eager <script type="module"> or modulepreload links in dist/index.html; the parser or the build output changed.');
  process.exit(1);
}

const offenders = [];
for (const assetPath of assets) {
  const file = path.join(distDir, assetPath.replace(/^\//, ''));
  if (!existsSync(file)) continue; // stylesheet, favicon, theme-init.js, ...
  const content = readFileSync(file, 'utf8');
  const hit = FINGERPRINTS.find((f) => content.includes(f));
  if (hit) offenders.push({ assetPath, hit });
}

if (offenders.length > 0) {
  console.error('check-chunks: tldts (public suffix list) found in an eagerly-loaded chunk:');
  for (const { assetPath, hit } of offenders) console.error(`  ${assetPath} (matched "${hit}")`);
  console.error('It must only be reachable from a lazily-loaded route (dynamic import()), e.g. the certificate wizard or Settings -> Issuance defaults.');
  process.exit(1);
}

console.log(`check-chunks: OK — ${assets.length} eager asset(s) checked, tldts not found.`);
