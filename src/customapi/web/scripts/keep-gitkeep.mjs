// Keeps web/dist/.gitkeep present after a build.
//
// vite.config.ts uses `emptyOutDir: true`, which wipes dist/ (including the
// .gitkeep that keeps the directory in a clean checkout). This postbuild step
// writes it back, so the invariant "dist/.gitkeep always exists" survives every
// `npm run build`.
import { existsSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const target = join(here, '..', 'dist', '.gitkeep')

const CONTENTS = `The built single-page app is written here by \`npm run build\` (vite outDir).
Files in this directory are embedded into the Go binary by internal/gateway/web.go.
This placeholder keeps the directory present so a Go build succeeds before the
front end has ever been built.
`

if (!existsSync(target)) {
  writeFileSync(target, CONTENTS, 'utf8')
  console.log('postbuild: wrote dist/.gitkeep')
}
