import test from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const root = dirname(dirname(fileURLToPath(import.meta.url)))
const profileModules = process.env.HARD_GATE_NODE_MODULES

test('the Config schema validates and fills defaults when schemastery is resolvable', { skip: !profileModules }, async () => {
  const pluginUrl = pathToFileURL(join(root, 'lib', 'index.js')).href
  const script = `
    const module = await import(${JSON.stringify(pluginUrl)})
    if (typeof module.Config !== 'function') throw new Error('Config is missing')
    const filled = module.Config({ shellOutsideWorkspace: 'ask', extraRoots: ['~/x'] })
    if (filled.shellOutsideWorkspace !== 'ask') throw new Error('value not preserved')
    if (filled.maxMutationsPerWindow !== 25) throw new Error('default not filled')
    if (filled.enforceWorkspaceOnly !== true) throw new Error('boolean default not filled')
    let rejected = false
    try { module.Config({ shellOutsideWorkspace: 'nope' }) } catch { rejected = true }
    if (!rejected) throw new Error('invalid value accepted')
    console.log('schema-ok')
  `

  const { stdout } = await run(process.execPath, ['--input-type=module', '--eval', script], {
    cwd: root,
    env: { ...process.env, NODE_PATH: profileModules },
  })

  assert.match(stdout, /schema-ok/)
})
