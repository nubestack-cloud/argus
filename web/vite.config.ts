import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  // Where the real ARGUS hub API lives. Defaults to the hub's own default
  // listen address so `npm run dev` works against a locally-running hub
  // with zero extra config. Override with VITE_API_BASE_URL in a .env file
  // (see .env.example) to point at a different hub.
  const apiBaseUrl = env.VITE_API_BASE_URL || 'http://localhost:8080'

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          target: apiBaseUrl,
          changeOrigin: true,
        },
      },
    },
    // BACKLOG P3. This project had no frontend test framework at all — typecheck,
    // lint and build only, against 389 Go test functions.
    //
    // `environment: 'jsdom'` per-file rather than globally would be tidier, but
    // most of what is worth testing here is pure logic (formatters, derivations,
    // enum-drift guards) that needs no DOM at all; setting jsdom once keeps the
    // component tests working without every pure test file carrying a pragma.
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/test/setup.ts'],
      // Excludes the default `**/node_modules/**` plus the built output, so a
      // stale dist/ cannot contribute phantom tests. `e2e/**` (BACKLOG.md P3's
      // Playwright suite, playwright.config.ts) is its own separate runner —
      // its specs import `test`/`expect` from `@playwright/test`, not Vitest's
      // globals, and Vitest's default include glob (`**/*.{test,spec}.*`)
      // would otherwise pick them up and fail them with a runner mismatch
      // error instead of running them for real against a browser.
      exclude: ['node_modules/**', 'dist/**', 'e2e/**'],
    },
  }
})
