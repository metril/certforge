(function () {
  var dark;
  try {
    var pref = localStorage.getItem('cf-theme');
    dark = pref === 'dark' || (pref !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  } catch {
    dark = false;
  }
  var root = document.documentElement;
  root.setAttribute('data-theme', dark ? 'dark' : 'light');
  root.style.colorScheme = dark ? 'dark' : 'light';
})();

// Re-review fix (M5's corrected CSP check surfaced this): zod v4 lazily
// probes `Function('')` the first time it needs to decide whether to
// JIT-compile a schema, to fall back gracefully in engines that disallow
// eval (its own doc comment: "Useful in environments that disallow eval").
// It catches the resulting exception and degrades fine either way, but our
// `script-src 'self'` CSP (no `unsafe-eval`, intentionally — this is not a
// place to weaken it) still makes the browser report a
// securitypolicyviolation for the attempt, on every page, the first time
// any zod schema is used (route search-param validation, present on every
// route). zod's own documented escape hatch is `z.config({ jitless: true })`,
// but nothing guarantees that call runs before some other module's
// top-level code first touches a zod schema; setting the same global it
// reads (`globalThis.__zod_globalConfig`) here, in the one script this app
// already guarantees runs before any module script (same reason theme-init
// itself has to be an external file rather than an inline <script>, which
// `script-src 'self'` with no `unsafe-inline` blocks), removes that race
// entirely — every zod-loaded copy shares this one global object.
globalThis.__zod_globalConfig = { jitless: true };
