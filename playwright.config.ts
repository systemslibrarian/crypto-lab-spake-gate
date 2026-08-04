import { defineConfig } from '@playwright/test'

// The a11y gate runs against `vite preview`, so what passes is what ships.
// vite base is '/crypto-lab-spake-gate/', so preview serves under that subpath.
export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4670/crypto-lab-spake-gate/',
    colorScheme: 'dark',
  },
  webServer: {
    // Build before serving: `preview` only serves whatever is already in dist/,
    // so a failed build would leave the last good bundle on disk and the suite
    // would pass green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4670 --strictPort',
    url: 'http://localhost:4670/crypto-lab-spake-gate/',
    reuseExistingServer: !process.env.CI,
  },
})
