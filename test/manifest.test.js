import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { resolveConfig } from '../lib/gate.js'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

test('the manifest wires a bundle patch that exists', async () => {
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
  assert.equal(manifest.type, 'module')
  assert.equal(manifest.exports['.'], './lib/index.js')
  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')

  for (const file of ['lib/index.js', 'cordis.patch.yml', 'icon.svg', 'locale/en.json', 'locale/zh.json']) {
    await stat(join(root, file))
  }
  assert.ok(manifest.files.includes('lib'))
  assert.ok(manifest.files.includes('locale'))
  assert.ok(manifest.files.includes('cordis.patch.yml'))
  assert.ok(manifest.files.includes('icon.svg'))
})

test('the patch inserts the gate under the package name', async () => {
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
  const patch = await readFile(join(root, 'cordis.patch.yml'), 'utf8')
  assert.match(patch, /-\s+id:\s*hard-gate/)
  assert.ok(patch.includes(`name: ${manifest.name}`))
})

test('the locale files carry real metadata', async () => {
  for (const locale of ['en', 'zh']) {
    const json = JSON.parse(await readFile(join(root, 'locale', `${locale}.json`), 'utf8'))
    assert.ok(json.meta.title.length > 0, `${locale} title`)
    assert.ok(json.meta.description.length > 20, `${locale} description`)
  }
})

test('every Config field has a runtime default', async () => {
  const source = await readFile(join(root, 'lib', 'index.js'), 'utf8')
  const keys = [...source.matchAll(/^\s{2,}(\w+): schema\./gm)].map((match) => match[1])
  assert.ok(keys.length >= 20, `expected the schema fields, found ${keys.length}`)

  // These are consumed by resolveConfig rather than echoed back under the same
  // name (the budget exposes softLimit/hardLimit/perFileLimit).
  const consumed = new Set(['replaceProtectedPaths', 'maxMutationsPerWindow', 'hardMutationCap', 'maxWritesPerFile'])
  const config = resolveConfig({})
  for (const key of keys) {
    if (consumed.has(key)) continue
    assert.ok(Object.hasOwn(config, key), `missing runtime default for ${key}`)
  }
})
