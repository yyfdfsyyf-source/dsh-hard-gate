import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createGate, resolveConfig } from '../lib/gate.js'

const session = {}
const next = async () => ({ kind: 'allow' })
const call = (name, args) => ({ name, arguments: args, agent: { session } })

async function makeWorkspace() {
  return mkdtemp(join(tmpdir(), 'hard-gate-'))
}

function makeGate(workspace, config = {}) {
  const ctx = {
    workingDirectory: { get: () => workspace },
    logger: { info() {}, warn() {} },
  }
  // Existing rule tests opt out of restore points; backup.test.js and the
  // integration cases below opt back in with a temp store.
  return createGate(ctx, { backupEnabled: false, ...config })
}

test('writes outside the workspace are denied', async () => {
  const workspace = await makeWorkspace()
  const outside = join(await makeWorkspace(), 'x.txt')
  const gate = makeGate(workspace)

  const decision = await gate.preExecute(call('write', { file_path: outside, content: 'x' }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /outside-workspace/)
})

test('writes to a protected path are denied in every mode', async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace, { enforceWorkspaceOnly: false })

  const decision = await gate.preExecute(call('edit', { file_path: join(workspace, '.git', 'config'), old_string: 'a', new_string: 'b' }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /protected-path/)
})

test('the platform protected roots always apply', { skip: process.platform !== 'win32' }, async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace, { enforceWorkspaceOnly: false, extraRoots: ['C:\\Windows'] })

  const decision = await gate.preExecute(call('write', { file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', content: 'x' }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /protected-path/)
})

test('a whole-file write needs a read to EOF', async () => {
  const workspace = await makeWorkspace()
  const file = join(workspace, 'a.txt')
  await writeFile(file, 'one\ntwo\nthree\n')
  const gate = makeGate(workspace)
  const envelope = (body) => `<path>${file}</path>\n<type>file</type>\n<content>\n${body}\n</content>`

  const missing = await gate.preExecute(call('write', { file_path: file, content: 'x' }), next)
  assert.match(missing.reason, /full-view-missing/)

  // The rendered footer inside a real envelope, plus the structured metadata
  // the tool attaches to every read result.
  await gate.observe(call('read', { file_path: file }), {
    content: [{ type: 'text', text: envelope('1: one\n2: two\n\n(Showing lines 1-2 of 3. Use offset=3 to continue.)') }],
    meta: { path: file, offset: 1, lines: [{ number: 1, text: 'one' }, { number: 2, text: 'two' }], totalLines: 3 },
  })
  const partial = await gate.preExecute(call('write', { file_path: file, content: 'x' }), next)
  assert.match(partial.reason, /full-view-partial/)

  await gate.observe(call('read', { file_path: file }), {
    content: [{ type: 'text', text: envelope('1: one\n2: two\n3: three\n\n(End of file - total 3 lines)') }],
    meta: {
      path: file,
      offset: 1,
      lines: [{ number: 1, text: 'one' }, { number: 2, text: 'two' }, { number: 3, text: 'three' }],
      totalLines: 3,
    },
  })
  const complete = await gate.preExecute(call('write', { file_path: file, content: 'replacement' }), next)
  assert.equal(complete.kind, 'allow')
})

test('a footer without structured metadata still proves a partial read', async () => {
  const workspace = await makeWorkspace()
  const file = join(workspace, 'no-meta.txt')
  await writeFile(file, 'a\nb\n')
  const gate = makeGate(workspace)

  await gate.observe(call('read', { file_path: file }), {
    content: [{ type: 'text', text: `<content>\n1: a\n\n(Showing lines 1-1 of 2. Use offset=2 to continue.)\n</content>` }],
  })
  const decision = await gate.preExecute(call('write', { file_path: file, content: 'x' }), next)
  assert.match(decision.reason, /full-view-partial/)
})

test('a gap between two reads still counts as partial', async () => {
  const workspace = await makeWorkspace()
  const file = join(workspace, 'gaps.txt')
  await writeFile(file, Array.from({ length: 600 }, (_, index) => `line ${index + 1}`).join('\n') + '\n')
  const gate = makeGate(workspace)

  // Two windows that each reach the end of the file, but leave 201-400 unseen.
  const window = (start, end) => ({
    content: [{ type: 'text', text: '<content>\n\n(Showing lines. Use offset to continue.)\n</content>' }],
    meta: {
      path: file,
      offset: start,
      lines: Array.from({ length: end - start + 1 }, (_, index) => ({ number: start + index, text: 'x' })),
      totalLines: 600,
    },
  })

  await gate.observe(call('read', { file_path: file, offset: 1, limit: 200 }), window(1, 200))
  await gate.observe(call('read', { file_path: file, offset: 401, limit: 200 }), window(401, 600))

  const denied = await gate.preExecute(call('write', { file_path: file, content: 'x' }), next)
  assert.match(denied.reason, /full-view-partial/)
  assert.match(denied.reason, /201-400/)

  await gate.observe(call('read', { file_path: file, offset: 201, limit: 200 }), window(201, 400))
  const allowed = await gate.preExecute(call('write', { file_path: file, content: 'x' }), next)
  assert.equal(allowed.kind, 'allow')
})

test('a write after an out-of-band change is refused', async () => {
  const workspace = await makeWorkspace()
  const file = join(workspace, 'b.txt')
  await writeFile(file, 'one\n')
  const gate = makeGate(workspace)

  await gate.observe(call('read', { file_path: file }), {
    content: [{ type: 'text', text: 'one\n(End of file - total 1 lines)' }],
  })
  await writeFile(file, 'one plus a lot more content\n')

  const decision = await gate.preExecute(call('write', { file_path: file, content: 'x' }), next)
  assert.match(decision.reason, /full-view-stale/)
})

test('a targeted edit does not need a full read', async () => {
  const workspace = await makeWorkspace()
  const file = join(workspace, 'c.txt')
  await writeFile(file, 'hello\n')
  const gate = makeGate(workspace)

  const decision = await gate.preExecute(call('edit', { file_path: file, old_string: 'hello', new_string: 'bye' }), next)
  assert.equal(decision.kind, 'allow')
})

test('the mutation budget asks, then refuses', async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace, { maxMutationsPerWindow: 2, hardMutationCap: 3, windowMs: 60_000 })

  const verdicts = []
  for (let index = 0; index < 4; index += 1) {
    const decision = await gate.preExecute(call('write', { file_path: join(workspace, `f-${index}.txt`), content: 'x' }), next)
    verdicts.push(decision.kind)
  }
  assert.deepEqual(verdicts, ['allow', 'allow', 'ask', 'deny'])
})

test('shell rules run through the gate', async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace)

  assert.equal((await gate.preExecute(call('pwsh', { command: 'Remove-Item -Recurse -Force C:\\' }), next)).kind, 'deny')
  assert.equal((await gate.preExecute(call('pwsh', { command: 'git clean -fdx' }), next)).kind, 'deny')
  assert.equal((await gate.preExecute(call('pwsh', { command: 'rm -rf node_modules' }), next)).kind, 'allow')
  assert.equal((await gate.preExecute(call('pwsh', { command: 'rm -rf src' }), next)).kind, 'ask')
})

test('a relative delete under an out-of-workspace workdir is denied', async () => {
  const workspace = await makeWorkspace()
  const outside = await makeWorkspace()
  const gate = makeGate(workspace)

  const decision = await gate.preExecute(call('pwsh', { command: 'Remove-Item -Recurse -Force .', workdir: outside }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /outside-workspace/)
})

test('programmatic tool calls with direct mutation ask', async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace)

  const decision = await gate.preExecute(call('run_code', { code: 'await import("node:fs").then((fs) => fs.rmSync(target))' }), next)
  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /program-fs-mutation/)
})

test('file tools may not request a wider sandbox mode', async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace)

  const decision = await gate.preExecute(call('write', { file_path: join(workspace, 'd.txt'), content: 'x', sandbox_permissions: 'danger-full-access' }), next)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /file-tool-escalation/)
})

test('shell escalations need a real justification', async () => {
  const workspace = await makeWorkspace()
  const gate = makeGate(workspace)

  const thin = await gate.preExecute(call('pwsh', { command: 'npm test', sandbox_permissions: 'danger-full-access', justification: 'x' }), next)
  assert.match(thin.reason, /missing-justification/)

  const real = await gate.preExecute(call('pwsh', { command: 'npm test', sandbox_permissions: 'danger-full-access', justification: 'tests need to read the sibling fixture repository' }), next)
  assert.equal(real.kind, 'allow')
})

test('str_replace_editor view is a read and is left alone', async () => {
  const workspace = await makeWorkspace()
  const outside = join(await makeWorkspace(), 'x.txt')
  const gate = makeGate(workspace)

  const decision = await gate.preExecute(call('str_replace_editor', { command: 'view', path: outside }), next)
  assert.equal(decision.kind, 'allow')
})

test('allowPaths relaxes containment but never protection', async () => {
  const workspace = await makeWorkspace()
  const outside = await makeWorkspace()
  const gate = makeGate(workspace, { allowPaths: [outside] })

  const allowed = await gate.preExecute(call('write', { file_path: join(outside, 'ok.txt'), content: 'x' }), next)
  assert.equal(allowed.kind, 'allow')

  const protectedWrite = await gate.preExecute(call('write', { file_path: join(workspace, '.git', 'HEAD'), content: 'x' }), next)
  assert.match(protectedWrite.reason, /protected-path/)
})

test('the monotonic guard refuses what the waterfall refuses', async () => {
  const workspace = await makeWorkspace()
  const outside = join(await makeWorkspace(), 'x.txt')
  const gate = makeGate(workspace)

  assert.equal(typeof gate.hardGuard(call('write', { file_path: outside, content: 'x' })), 'string')
  assert.equal(typeof gate.hardGuard(call('write', { file_path: join(workspace, '.git', 'config'), content: 'x' })), 'string')
  assert.equal(gate.hardGuard(call('write', { file_path: join(workspace, 'ok.txt'), content: 'x' })), undefined)
  assert.equal(gate.hardGuard(call('read', { file_path: outside })), undefined, 'reads are never guarded')
  assert.equal(
    gate.hardGuard(call('str_replace_editor', { command: 'view', path: outside })),
    undefined,
    'view is a read and must not be judged by path',
  )
  assert.equal(
    typeof gate.hardGuard(call('str_replace_editor', { command: 'create', path: outside })),
    'string',
    'create is a mutation',
  )
})

test('resolveConfig keeps the documented defaults', () => {
  const config = resolveConfig({})
  assert.equal(config.enforceWorkspaceOnly, true)
  assert.equal(config.requireFullRead, true)
  assert.equal(config.shellOutsideWorkspace, 'deny')
  assert.equal(config.softLimit, 25)
  assert.equal(config.hardLimit, 60)
  assert.ok(config.protectedPaths.length > 0)
  assert.equal(config.mutationTools.write, 'file_path')
})

test('ruleSeverity parses overrides and ignores invalid values', () => {
  const config = resolveConfig({
    ruleSeverity: { 'git-destructive': 'deny', publish: 'off', elevate: 'bogus', secret: 'allow' },
  })
  assert.equal(config.ruleSeverity['git-destructive'], 'deny')
  assert.equal(config.ruleSeverity.publish, 'off')
  assert.equal(config.ruleSeverity.secret, 'allow')
  assert.equal(config.ruleSeverity.elevate, undefined)
  assert.deepEqual(resolveConfig({}).ruleSeverity, {})
})

test('ruleSeverity can escalate, downgrade and disable shell rules', async () => {
  const workspace = await makeWorkspace()
  const shell = (cmd, rules) => makeGate(workspace, { ruleSeverity: rules }).preExecute(
    call('pwsh', { command: cmd }), next,
  )

  // Default: git push --force asks.
  assert.equal((await shell('git push --force origin main', {})).kind, 'ask')
  // Escalated to deny.
  assert.equal((await shell('git push --force origin main', { 'git-destructive': 'deny' })).kind, 'deny')
  // Downgraded to allow.
  assert.equal((await shell('git push --force origin main', { 'git-destructive': 'allow' })).kind, 'allow')
  // Turned off entirely (next() result is returned).
  assert.equal((await shell('git push --force origin main', { 'git-destructive': 'off' })).kind, 'allow')
  // A deny rule can be downgraded to ask.
  assert.equal((await shell('Remove-Item -Recurse -Force C:\\', { 'catastrophic-target': 'ask' })).kind, 'ask')
  // A deny rule can be turned off.
  assert.equal((await shell('Remove-Item -Recurse -Force C:\\', { 'catastrophic-target': 'off' })).kind, 'allow')
  // Unrelated rules are unaffected.
  assert.equal((await shell('git clean -fdx', { 'git-destructive': 'off' })).kind, 'deny')
})
