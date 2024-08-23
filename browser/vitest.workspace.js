import { defineWorkspace } from 'vitest/config'

export default defineWorkspace([
  "./lib/vite.config.ts",
  "./svelte/vite.config.ts",
  "./data-browser/vite.config.ts"
])
