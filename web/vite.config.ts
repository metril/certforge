import path from 'node:path';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { tanstackRouter } from '@tanstack/router-plugin/vite';

// Adaptation (preflight B1): default to CF_HTTP_PORT so a non-default backend
// port (this host runs the dev API on 18080; 8080 is taken by something else)
// works without CF_DEV_BACKEND.
const backend = process.env.CF_DEV_BACKEND ?? `http://localhost:${process.env.CF_HTTP_PORT ?? 8080}`;

export default defineConfig({
  plugins: [tanstackRouter({ target: 'react', autoCodeSplitting: true }), react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
  server: {
    proxy: { '/api': backend, '/readyz': backend, '/healthz': backend },
  },
  build: { outDir: 'dist', sourcemap: true, emptyOutDir: true },
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'http://localhost:3000/' } },
    setupFiles: ['src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
  },
});
