import test from 'node:test'
import assert from 'node:assert/strict'
import * as plugin from '../lib/index.js'

const isWindows = process.platform === 'win32'

function fakeContext(workspace) {
  const registered = []
  const guards = []
  const effects = []
  const ctx = {
    tools: {
      guard: (fn) => {
        guards.push(fn)
        return () => {
          const index = guards.indexOf(fn)
          if (index >= 0) guards.splice(index, 1)
        }
      },
    },
    workingDirectory: { get: () => workspace },
    logger: { info() {}, warn() {} },
    on: (event, fn, options) => {
      registered.push({ event, fn, options })
      return () => {}
    },
    effect: (fn, label) => {
      effects.push({ fn, label })
      return () => {}
    },
  }
  return { ctx, registered, guards, effects }
}

test('loads as a host plugin even when schemastery is not resolvable', () => {
  assert.equal(plugin.name, 'hard-gate')
  assert.deepEqual(plugin.inject, ['tools', 'workingDirectory'])
  assert.equal(typeof plugin.apply, 'function')
  assert.ok(plugin.Config === undefined || typeof plugin.Config === 'function')
})

test('apply registers a prepended policy listener, a result observer, and a guard', () => {
  const workspace = isWindows ? 'C:\\work' : '/work'
  const { ctx, registered, guards, effects } = fakeContext(workspace)
  plugin.apply(ctx, {})

  const pre = registered.find((entry) => entry.event === 'tools/pre-execute')
  assert.equal(pre?.options?.prepend, true)
  assert.equal(typeof pre.fn, 'function')
  assert.equal(registered.some((entry) => entry.event === 'tools/result'), true)
  assert.equal(guards.length, 1)

  for (const effect of effects) {
    const dispose = effect.fn()
    if (typeof dispose === 'function') dispose()
  }
})

test('the wired listener denies an out-of-workspace write', async () => {
  const workspace = isWindows ? 'C:\\work' : '/work'
  const outside = isWindows ? 'C:\\outside\\x.txt' : '/outside/x.txt'
  const { ctx, registered } = fakeContext(workspace)
  plugin.apply(ctx, {})

  const pre = registered.find((entry) => entry.event === 'tools/pre-execute').fn
  const decision = await pre(
    { name: 'write', arguments: { file_path: outside, content: 'x' }, agent: { session: {} } },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /outside-workspace/)
})

test('the wired listener leaves a call without an agent to the host', async () => {
  const { ctx, registered } = fakeContext(isWindows ? 'C:\\work' : '/work')
  plugin.apply(ctx, {})
  const pre = registered.find((entry) => entry.event === 'tools/pre-execute').fn
  const decision = await pre({ name: 'write', arguments: { file_path: 'x' } }, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
})
