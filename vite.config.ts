import { defineConfig } from 'vitest/config'

// base must match the GitHub Pages project subpath (repo name).
export default defineConfig({
  base: '/crypto-lab-spake-gate/',
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
