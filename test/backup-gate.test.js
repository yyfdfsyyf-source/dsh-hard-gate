import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readIndex } from '../lib/backup.js'
import { createGate } from '../lib/gate.js'
import { readZip } from '../lib/zip.js'

const session = {}
const next = async () => ({ kind: 'allow' })
const call = (name, args) => ({ name, arguments: args, agent: { session } })

async function setup(config = {}) {
  const workspace = await mkdtemp(join(tmpdir(), 'hard-gate-gate-ws-'))
  const storeDir = await mkdtemp(join(tmpdir(), 'hard-gate-gate-store-'))
  const gate = createGate({
    workingDirectory: { get: () => workspace },
    logger: { info() {}, warn() {} },
  }, {
    backupEnabled: true,
    backupDir: storeDir,
    recycleBin: 'never',
    retentionDays: 0,
    maxTotalBytes: 0,
    ...config,
  })
  return { workspace, storeDir, gate }
}

/** Mark a file as fully read without depending on the read tool's envelope. */
async function readFully(gate, file) {
  await gate.observe(call('read', { file_path: file }), {
    content: [{ type: 'text', text: 'seen\n' }],
  })
}

test('a whole-file overwrite takes a restore point first', async () => {
  const { workspace, storeDir, gate } = await setup()
  const file = join(workspace, 'a.txt')
  await writeFile(file, 'original\n')
  await readFully(gate, file)

  const decision = await gate.preExecute(call('write', { file_path: file, content: 'replacement\n' }), next)
  assert.equal(decision.kind, 'allow')

  const index = await readIndex(storeDir)
  assert.equal(index.length, 1)
  assert.equal(index[0].rule, 'file:write')
  assert.equal(index[0].files, 1)

  const entries = await readZip(await readFile(index[0].zip))
  const manifest = JSON.parse(entries.find((entry) => entry.name.endsWith('manifest.json')).data.toString('utf8'))
  assert.equal(manifest.tool, 'write')
  assert.equal(manifest.items[0].path, file)
  assert.equal(entries.find((entry) => entry.name === 'a.txt').data.toString('utf8'), 'original\n')
})

test('creating a new file does not create an empty restore point', async () => {
  const { workspace, storeDir, gate } = await setup()
  const decision = await gate.preExecute(call('write', { file_path: join(workspace, 'new.txt'), content: 'x' }), next)
  assert.equal(decision.kind, 'allow')
  assert.deepEqual(await readIndex(storeDir), [])
})

test('a denied write never reaches the backup layer', async () => {
  const { storeDir, gate } = await setup()
  const outside = join(await mkdtemp(join(tmpdir(), 'hard-gate-outside-')), 'x.txt')
  const decision = await gate.preExecute(call('write', { file_path: outside, content: 'x' }), next)
  assert.equal(decision.kind, 'deny')
  assert.deepEqual(await readIndex(storeDir), [])
})

test('a targeted edit also takes a restore point', async () => {
  const { workspace, storeDir, gate } = await setup()
  const file = join(workspace, 'b.txt')
  await writeFile(file, 'hello\n')
  const decision = await gate.preExecute(call('edit', { file_path: file, old_string: 'hello', new_string: 'bye' }), next)
  assert.equal(decision.kind, 'allow')
  const index = await readIndex(storeDir)
  assert.equal(index.length, 1)
  assert.equal(index[0].rule, 'file:edit')
})

test('backupEdits: false leaves targeted edits without a restore point', async () => {
  const { workspace, storeDir, gate } = await setup({ backupEdits: false })
  const file = join(workspace, 'c.txt')
  await writeFile(file, 'hello\n')
  const decision = await gate.preExecute(call('edit', { file_path: file, old_string: 'hello', new_string: 'bye' }), next)
  assert.equal(decision.kind, 'allow')
  assert.deepEqual(await readIndex(storeDir), [])
})

test('a recursive shell delete is backed up before the approval prompt', async () => {
  const { workspace, storeDir, gate } = await setup()
  await mkdir(join(workspace, 'src'), { recursive: true })
  await writeFile(join(workspace, 'src', 'a.txt'), 'alpha')

  const decision = await gate.preExecute(call('pwsh', { command: 'Remove-Item -Recurse -Force src' }), next)
  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /recursive-delete/)

  const index = await readIndex(storeDir)
  assert.equal(index.length, 1)
  assert.equal(index[0].rule, 'shell:recursive-delete')
  assert.equal(index[0].files, 1)
})

test('a shell overwrite is backed up too', async () => {
  const { workspace, storeDir, gate } = await setup()
  const file = join(workspace, 'notes.txt')
  await writeFile(file, 'old notes\n')

  const decision = await gate.preExecute(call('pwsh', { command: 'Set-Content notes.txt "new notes"' }), next)
  assert.equal(decision.kind, 'allow')
  const index = await readIndex(storeDir)
  assert.equal(index.length, 1)
  assert.equal(index[0].rule, 'shell:local-write')
})

test('deleting a regenerable directory stays silent and unarchived', async () => {
  const { workspace, storeDir, gate } = await setup()
  await mkdir(join(workspace, 'node_modules', 'pkg'), { recursive: true })
  await writeFile(join(workspace, 'node_modules', 'pkg', 'index.js'), 'x')

  const decision = await gate.preExecute(call('pwsh', { command: 'Remove-Item -Recurse -Force node_modules' }), next)
  assert.equal(decision.kind, 'allow')
  assert.deepEqual(await readIndex(storeDir), [])
})

test('an oversized restore point turns into an explicit ask', async () => {
  const { workspace, storeDir, gate } = await setup({ backupMaxBytes: 4 })
  const file = join(workspace, 'large.txt')
  await writeFile(file, 'x'.repeat(100))
  await readFully(gate, file)

  const decision = await gate.preExecute(call('write', { file_path: file, content: 'y' }), next)
  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /backup-failed/)
  assert.deepEqual(await readIndex(storeDir), [])
})

test('backupFailure: deny refuses the operation when no restore point can be made', async () => {
  const { workspace, gate } = await setup({ backupMaxBytes: 4, backupFailure: 'deny' })
  const file = join(workspace, 'large.txt')
  await writeFile(file, 'x'.repeat(100))
  await readFully(gate, file)

  const decision = await gate.preExecute(call('write', { file_path: file, content: 'y' }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /backup-failed/)
})

test('the restore-point store itself is a protected path', async () => {
  const { storeDir, gate } = await setup({ enforceWorkspaceOnly: false })
  const decision = await gate.preExecute(call('write', { file_path: join(storeDir, 'index.jsonl'), content: 'x' }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /protected-path/)
})
