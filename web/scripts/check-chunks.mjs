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
// Phase 6B final review: a second, independent guard — the `_app` layout
// chunk (every authenticated page; `src/routes/_app.tsx`) must never
// statically reach `@rjsf` (`SchemaForm`, ~270 KB): CommandPalette once
// imported `runBackup` straight from `features/settings/BackupSection`,
// which drags in `SchemaSection` → `SchemaForm` — even though `SchemaForm`
// itself stayed a separate chunk file (never inlined) and never showed up
// in `index.html`'s own eager modulepreload list (that list is the
// *pre-auth* entry graph; `_app` itself is a lazily-routed chunk, loaded
// the moment any authenticated page renders, not from index.html at all),
// so the first tldts-style check above didn't catch it. This one instead
// walks `_app`'s own static (`import`/`import … from`, never dynamic
// `import()`) dependency graph and fails if any reachable chunk carries the
// `@rjsf` fingerprint.
//
// tldts embeds the public suffix list; the ACE/punycode prefix `xn--` and
// the literal `publicsuffix` are its fingerprints (the actual code around
// them gets renamed by minification, these string/data literals do not).
// `@rjsf`'s own components hard-code a `rjsf-*` CSS class prefix
// (`rjsf-field`, `rjsf-array-item`, …) — also a string literal minification
// leaves alone.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
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

const TLDTS_FINGERPRINTS = ['xn--', 'publicsuffix'];

const assets = eagerAssetPaths(html);
if (assets.length === 0) {
  console.error('check-chunks: found no eager <script type="module"> or modulepreload links in dist/index.html; the parser or the build output changed.');
  process.exit(1);
}

const tldtsOffenders = [];
for (const assetPath of assets) {
  const file = path.join(distDir, assetPath.replace(/^\//, ''));
  if (!existsSync(file)) continue; // stylesheet, favicon, theme-init.js, ...
  const content = readFileSync(file, 'utf8');
  const hit = TLDTS_FINGERPRINTS.find((f) => content.includes(f));
  if (hit) tldtsOffenders.push({ assetPath, hit });
}

if (tldtsOffenders.length > 0) {
  console.error('check-chunks: tldts (public suffix list) found in an eagerly-loaded chunk:');
  for (const { assetPath, hit } of tldtsOffenders) console.error(`  ${assetPath} (matched "${hit}")`);
  console.error('It must only be reachable from a lazily-loaded route (dynamic import()), e.g. the certificate wizard or Settings -> Issuance defaults.');
  process.exit(1);
}

// --- _app must never statically reach @rjsf -------------------------------

const assetsDir = path.join(distDir, 'assets');
const assetFiles = existsSync(assetsDir) ? readdirSync(assetsDir) : [];
const appEntry = assetFiles.find((f) => /^_app-.*\.js$/.test(f) && !f.endsWith('.map'));
if (!appEntry) {
  console.error('check-chunks: no dist/assets/_app-*.js chunk found; the route file or build output changed.');
  process.exit(1);
}

/** Every chunk this file statically imports (default/named `from "./x.js"`
 * or bare side-effect `import "./x.js"`), never a dynamic `import("./x.js")`
 * — that call always has a `(` right after `import`, never a `"`, so the
 * two required prefixes below can never match it. */
function staticImportTargets(content) {
  const targets = new Set();
  for (const m of content.matchAll(/(?:from|import)"\.\/([A-Za-z0-9_.$-]+\.js)"/g)) targets.add(m[1]);
  return targets;
}

const reachableFromApp = new Set();
const queue = [appEntry];
while (queue.length > 0) {
  const name = queue.shift();
  if (reachableFromApp.has(name)) continue;
  reachableFromApp.add(name);
  const file = path.join(assetsDir, name);
  if (!existsSync(file)) continue;
  for (const dep of staticImportTargets(readFileSync(file, 'utf8'))) {
    if (!reachableFromApp.has(dep)) queue.push(dep);
  }
}

const RJSF_FINGERPRINTS = ['rjsf-field', 'rjsf-array-item'];
const rjsfOffenders = [];
for (const name of reachableFromApp) {
  const content = readFileSync(path.join(assetsDir, name), 'utf8');
  const hit = RJSF_FINGERPRINTS.find((f) => content.includes(f));
  if (hit) rjsfOffenders.push({ name, hit });
}

if (rjsfOffenders.length > 0) {
  console.error(`check-chunks: @rjsf (SchemaForm) is statically reachable from ${appEntry} (the _app layout, loaded for every authenticated page):`);
  for (const { name, hit } of rjsfOffenders) console.error(`  ${name} (matched "${hit}")`);
  console.error('A component only Settings needs (e.g. a settings-section helper) must be imported by a shared caller (CommandPalette, AppShell, ...) from a plain module (api/queries/*, lib/*), never from the settings feature module that pulls SchemaForm in with it.');
  process.exit(1);
}

console.log(`check-chunks: OK — ${assets.length} eager asset(s) checked, tldts not found; ${reachableFromApp.size} chunk(s) reachable from ${appEntry}, @rjsf not found.`);
