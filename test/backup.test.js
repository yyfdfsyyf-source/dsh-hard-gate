import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createBackupStore, readIndex, restoreRecord } from '../lib/backup.js'

const logger = { info() {}, warn() {} }

async function workspace() {
  return mkdtemp(join(tmpdir(), 'hard-gate-backup-ws-'))
}

async function storeDir() {
  return mkdtemp(join(tmpdir(), 'hard-gate-backup-store-'))
}

function makeStore(dir, options = {}) {
  return createBackupStore({ logger }, {
    dir,
    enabled: true,
    recycleBin: 'never',
    retentionDays: 0,
    maxTotalBytes: 0,
    ...options,
  })
}

test('a directory backup restores the whole tree', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  await mkdir(join(root, 'src', 'nested'), { recursive: true })
  await writeFile(join(root, 'src', 'a.txt'), 'alpha')
  await writeFile(join(root, 'src', 'nested', 'b.txt'), 'beta')

  const store = makeStore(storePath)
  const result = await store.backup([join(root, 'src')], {
    tool: 'pwsh',
    rule: 'shell:recursive-delete',
    cwd: root,
    roots: [root],
    bin: false,
  })

  assert.equal(result.ok, true)
  assert.equal(result.files, 2)
  assert.equal(result.empty, undefined)

  const index = await readIndex(storePath)
  assert.equal(index.length, 1)
  assert.equal(index[0].id, result.id)
  assert.equal(index[0].files, 2)
  assert.equal(index[0].tool, 'pwsh')

  await rm(join(root, 'src'), { recursive: true })
  const restored = await restoreRecord(index[0], { force: true })
  assert.equal(restored.restored.length, 2)
  assert.equal(await readFile(join(root, 'src', 'a.txt'), 'utf8'), 'alpha')
  assert.equal(await readFile(join(root, 'src', 'nested', 'b.txt'), 'utf8'), 'beta')
})

test('empty directories are recorded and recreated', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  await mkdir(join(root, 'tree', 'empty'), { recursive: true })
  await writeFile(join(root, 'tree', 'a.txt'), 'alpha')

  const store = makeStore(storePath)
  const result = await store.backup([join(root, 'tree')], {
    tool: 'pwsh',
    rule: 'shell:recursive-delete',
    cwd: root,
    roots: [root],
    bin: false,
  })
  assert.equal(result.ok, true)
  assert.ok(result.files >= 2)

  const index = await readIndex(storePath)
  await rm(join(root, 'tree'), { recursive: true })
  const restored = await restoreRecord(index[0], { force: true })
  assert.ok(restored.restored.includes(join(root, 'tree', 'empty')))
  assert.equal((await stat(join(root, 'tree', 'empty'))).isDirectory(), true)
  assert.equal(await readFile(join(root, 'tree', 'a.txt'), 'utf8'), 'alpha')
})

test('restore refuses to replace a directory even with force', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const file = join(root, 'a.txt')
  await writeFile(file, 'original')

  const store = makeStore(storePath)
  await store.backup([file], { tool: 'edit', rule: 'file:edit', cwd: root, roots: [root], bin: false })
  const index = await readIndex(storePath)

  await rm(file)
  await mkdir(file)
  const restored = await restoreRecord(index[0], { force: true })
  assert.deepEqual(restored.restored, [])
  assert.equal(restored.skipped.length, 1)
  assert.match(restored.skipped[0].reason, /not a regular file/)
})

test('restore preserves the recorded mtime', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const file = join(root, 'a.txt')
  const stamp = new Date('2020-01-02T03:04:05Z')
  await writeFile(file, 'original')
  await utimes(file, stamp, stamp)

  const store = makeStore(storePath)
  await store.backup([file], { tool: 'edit', rule: 'file:edit', cwd: root, roots: [root], bin: false })
  const index = await readIndex(storePath)

  await rm(file)
  await restoreRecord(index[0], { force: true })
  const info = await stat(file)
  assert.ok(Math.abs(info.mtimeMs - stamp.getTime()) < 2000)
})

test('restore refuses to overwrite unless forced', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const file = join(root, 'a.txt')
  await writeFile(file, 'original')

  const store = makeStore(storePath)
  const result = await store.backup([file], { tool: 'edit', rule: 'file:edit', cwd: root, roots: [root], bin: false })
  assert.equal(result.files, 1)

  await writeFile(file, 'changed')
  const index = await readIndex(storePath)
  const blocked = await restoreRecord(index[0])
  assert.deepEqual(blocked.conflicts, [file])
  assert.equal(await readFile(file, 'utf8'), 'changed')

  const forced = await restoreRecord(index[0], { force: true })
  assert.deepEqual(forced.restored, [file])
  assert.equal(await readFile(file, 'utf8'), 'original')
})

test('a dry run reports without writing', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const file = join(root, 'a.txt')
  await writeFile(file, 'original')

  const store = makeStore(storePath)
  await store.backup([file], { tool: 'edit', rule: 'file:edit', cwd: root, roots: [root], bin: false })
  await rm(file)

  const index = await readIndex(storePath)
  const preview = await restoreRecord(index[0], { dryRun: true })
  assert.deepEqual(preview.restored, [file])
  await assert.rejects(readFile(file), /ENOENT/)
})

test('a missing target produces no archive', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const store = makeStore(storePath)
  const result = await store.backup([join(root, 'never-existed.txt')], { tool: 'write', cwd: root, roots: [root], bin: false })
  assert.equal(result.ok, true)
  assert.equal(result.empty, true)
  assert.deepEqual(await readIndex(storePath), [])
})

test('the size cap refuses the backup instead of silently skipping it', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const file = join(root, 'big.bin')
  await writeFile(file, Buffer.alloc(64, 7))

  const store = makeStore(storePath, { maxBytes: 16 })
  await assert.rejects(
    store.backup([file], { tool: 'write', cwd: root, roots: [root], bin: false }),
    (error) => error.name === 'BackupLimitError' && /exceed/.test(error.message),
  )
})

test('regenerable directories are not archived', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  await mkdir(join(root, 'node_modules', 'pkg'), { recursive: true })
  await writeFile(join(root, 'node_modules', 'pkg', 'index.js'), 'x')

  const store = makeStore(storePath, { skipDirs: ['node_modules'] })
  const result = await store.backup([join(root, 'node_modules')], { tool: 'pwsh', cwd: root, roots: [root], bin: false })
  assert.equal(result.empty, true)
  assert.deepEqual(await readIndex(storePath), [])
})

test('the manifest keeps absolute paths and workspace roots', async () => {
  const root = await workspace()
  const storePath = await storeDir()
  const file = join(root, 'a.txt')
  await writeFile(file, 'x')

  const store = makeStore(storePath)
  await store.backup([file], { tool: 'write', rule: 'file:write', cwd: root, roots: [root], bin: false })
  const [record] = await readIndex(storePath)
  const { readZip } = await import('../lib/zip.js')
  const entries = await readZip(await readFile(record.zip))
  const manifest = JSON.parse(entries.find((entry) => entry.name.endsWith('manifest.json')).data.toString('utf8'))
  assert.equal(manifest.items[0].path, file)
  assert.deepEqual(manifest.roots, [root])
  assert.equal(manifest.complete, true)
})
