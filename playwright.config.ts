import { defineConfig } from '@playwright/test'

// The a11y gate runs against `vite preview`, so what passes is what ships.
// vite base is '/crypto-lab-spake-gate/', so preview serves under that subpath.
export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4173/crypto-lab-spake-gate/',
    colorScheme: 'dark',
  },
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173/crypto-lab-spake-gate/',
    reuseExistingServer: !process.env.CI,
  },
})
