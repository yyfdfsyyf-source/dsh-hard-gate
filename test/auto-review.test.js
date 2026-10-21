import test from 'node:test'
import assert from 'node:assert/strict'
import {
  REVIEW_POLICY,
  buildReviewText,
  installAutoReview,
  parseReviewDecision,
  reviewAction,
  reviewRoute,
} from '../lib/auto-review.js'

const WORK = 'C:\\work'
const AUTO = 'auto'

function textStream(text, { reasoning = false, finish = { kind: 'stop' } } = {}) {
  return (async function* stream() {
    let index = 0
    if (reasoning) {
      yield { type: 'block-start', index, blockType: 'reasoning' }
      yield { type: 'reasoning-delta', index, text: 'thinking' }
      yield { type: 'block-end', index, block: { type: 'reasoning', text: 'thinking' } }
      index += 1
    }
    yield { type: 'block-start', index, blockType: 'text' }
    yield { type: 'text-delta', index, text }
    yield { type: 'block-end', index, block: { type: 'text', text } }
    yield { type: 'finish', reason: finish }
  })()
}

function makeHarness(options = {}) {
  const state = {
    preset: options.preset ?? AUTO,
    approval: options.approval ?? 'ask',
    downstream: options.downstream ?? { kind: 'allow' },
    text: options.text ?? '{"risk":"low","decision":"allow"}',
    streamFactory: options.streamFactory,
    header: options.header ?? { config: { provider: 'session-provider', model: 'session-model' }, tools: [] },
    cwd: options.cwd ?? WORK,
    sessions: options.sessions ?? [{ id: 's1' }],
    modelCalls: [],
    setCalls: [],
    warnings: [],
    nextCalls: 0,
    autoRegistered: false,
    admit: undefined,
    effectErrors: [],
    effectDispose: undefined,
  }

  const handlers = []
  const permissionPresets = {
    get names() {
      return ['workspace-write', 'danger-full-access']
    },
    current: () => state.preset,
    registerAuto: (admit) => {
      if (options.autoConflict === true) throw new Error('permission: preset "auto" is already registered')
      state.autoRegistered = true
      state.admit = admit
      return () => {
        state.autoRegistered = false
      }
    },
    set: (session, name) => {
      state.setCalls.push({ session, name })
      state.preset = name
    },
  }
  const approval = { overrideOf: () => state.approval }
  const sessions = { list: () => state.sessions }
  const llm = {
    stream: (request) => {
      state.modelCalls.push(request)
      if (typeof state.streamFactory === 'function') return state.streamFactory(request)
      return textStream(state.text)
    },
  }
  const workingDirectory = { ensure: async () => state.cwd }
  const child = {
    permissionPresets,
    approval,
    sessions,
    llm,
    workingDirectory,
    logger: {
      info() {},
      warn: (message) => state.warnings.push(message),
    },
    on: (event, fn, opts) => {
      handlers.push({ event, fn, opts })
      return () => {
        const index = handlers.findIndex((entry) => entry.fn === fn)
        if (index >= 0) handlers.splice(index, 1)
      }
    },
    effect: (generator, label) => {
      const disposers = []
      try {
        const iterator = typeof generator === 'function' ? generator() : generator
        let result = iterator.next()
        while (!result.done) {
          if (typeof result.value === 'function') disposers.push(result.value)
          result = iterator.next()
        }
      } catch (error) {
        state.effectErrors.push(error)
      }
      const dispose = async () => {
        for (const fn of disposers.reverse()) await fn()
      }
      state.effectDispose = dispose
      state.effectLabel = label
      return dispose
    },
  }

  const ctx = {
    inject: (deps, callback) => {
      state.injectedDeps = deps
      callback(child)
      return () => {}
    },
  }

  installAutoReview(ctx, {
    autoReview: true,
    reviewProvider: options.reviewProvider ?? '',
    reviewModel: options.reviewModel ?? '',
    reviewReasoningEffort: options.reviewReasoningEffort ?? '',
    reviewReadOnly: options.reviewReadOnly ?? false,
    reviewTimeoutMs: options.reviewTimeoutMs ?? 30000,
  })

  const handler = handlers.find((entry) => entry.event === 'tools/pre-execute')?.fn
  return { state, handler, handlers, child }
}

function makeExec(state, name, args, extra = {}) {
  return {
    name,
    arguments: args,
    agent: { session: { requestHeader: () => state.header } },
    signal: new AbortController().signal,
    ...extra,
  }
}

function nextOf(state) {
  return async () => {
    state.nextCalls += 1
    return state.downstream
  }
}

test('the policy is context-free and denies every medium action', () => {
  assert.match(REVIEW_POLICY, /do NOT see the conversation/)
  assert.match(REVIEW_POLICY, /deny every medium action/)
  assert.match(REVIEW_POLICY, /do not see the conversation/i)
})

test('reviewRoute prefers an explicit pair and falls back to the session route', () => {
  assert.deepEqual(
    reviewRoute({ reviewProvider: 'p', reviewModel: 'm' }, { config: { provider: 'sp', model: 'sm' } }),
    { provider: 'p', model: 'm' },
  )
  assert.deepEqual(
    reviewRoute({}, { config: { provider: 'sp', model: 'sm' } }),
    { provider: 'sp', model: 'sm' },
  )
  assert.throws(() => reviewRoute({ reviewProvider: 'p' }, { config: { provider: 'sp', model: 'sm' } }), /together/)
  assert.throws(() => reviewRoute({}, undefined), /no reviewer route/)
})

test('reviewAction previews file bodies and keeps the shell command intact', () => {
  const header = {
    tools: [{ name: 'write', description: 'Write a file', parameters: { type: 'object' } }],
  }
  const content = 'x'.repeat(2000)
  const write = reviewAction({ name: 'write', arguments: { file_path: 'C:\\work\\a.txt', content } }, header, WORK)
  assert.equal(write.description, 'Write a file')
  assert.equal(write.mode, 'native')
  assert.equal(write.arguments.content.truncated, true)
  assert.equal(write.arguments.content.head.length, 600)
  assert.ok(!JSON.stringify(write).includes('x'.repeat(1000)))

  const shell = reviewAction({ name: 'bash', arguments: { command: 'rm -rf src' } }, { tools: [] }, WORK)
  assert.equal(shell.arguments.command, 'rm -rf src')

  const ptc = reviewAction(
    { name: 'bash', arguments: { command: 'ls' }, parent: {}, schema: { description: 'Run', parameters: { type: 'object' } } },
    { tools: [] },
    WORK,
  )
  assert.equal(ptc.mode, 'ptc-inner')
  assert.equal(ptc.description, 'Run')
})

test('buildReviewText emits one pending-action section', () => {
  assert.match(buildReviewText({ name: 'x', cwd: WORK }), /^PENDING_ACTION\n\n\{/)
})

test('parseReviewDecision accepts the closed protocol and fails closed on unsafe allows', () => {
  assert.deepEqual(parseReviewDecision('{"risk":"low","decision":"allow"}'), { decision: 'allow', risk: 'low' })
  assert.deepEqual(
    parseReviewDecision('```json\n{"risk":"low","decision":"allow"}\n```'),
    { decision: 'allow', risk: 'low' },
  )
  assert.deepEqual(
    parseReviewDecision('{"risk":"medium","decision":"deny","reason":"recursive delete"}'),
    { decision: 'deny', risk: 'medium', reason: 'recursive delete' },
  )
  assert.deepEqual(parseReviewDecision('{"risk":"low","decision":"deny"}'), { decision: 'deny', risk: 'low' })
  assert.deepEqual(
    parseReviewDecision('{"risk":"medium","decision":"allow"}'),
    { decision: 'deny', risk: 'medium', reason: 'reviewer tried to allow a medium-risk action without conversation context' },
  )
  assert.deepEqual(
    parseReviewDecision('{"risk":"high","decision":"allow"}'),
    { decision: 'deny', risk: 'high', reason: 'reviewer tried to allow a high-risk action without conversation context' },
  )
  assert.throws(() => parseReviewDecision('not json'), /valid JSON/)
  assert.throws(() => parseReviewDecision('{"risk":"low","decision":"allow","reason":"x"}'), /must not give a reason/)
  assert.throws(() => parseReviewDecision('{"risk":"low","risk":"high","decision":"allow"}'), /repeats/)
  assert.throws(() => parseReviewDecision('{"risk":"medium","decision":"deny","extra":true}'), /unexpected member/)
})

test('a low-risk allow reaches the next gate and uses a tiny context-free request', async () => {
  const { state, handler } = makeHarness({ text: '{"risk":"low","decision":"allow"}' })
  const decision = await handler(makeExec(state, 'bash', { command: 'ls -la' }), nextOf(state))

  assert.equal(decision.kind, 'allow')
  assert.equal(state.nextCalls, 1)
  assert.equal(state.modelCalls.length, 1)
  assert.equal(state.modelCalls[0].provider, 'session-provider')
  assert.equal(state.modelCalls[0].model, 'session-model')
  assert.equal(state.modelCalls[0].temperature, 0)
  assert.match(state.modelCalls[0].system, /REVIEW_POLICY/)
  const prompt = state.modelCalls[0].messages[0].content[0].text
  assert.match(prompt, /^PENDING_ACTION/)
  assert.match(prompt, /ls -la/)
  assert.ok(!prompt.includes('FILTERED_HISTORY'))
})

test('read-only tools and non-Auto sessions skip the reviewer', async () => {
  const readHarness = makeHarness()
  const readDecision = await readHarness.handler(makeExec(readHarness.state, 'read', { file_path: 'a.txt' }), nextOf(readHarness.state))
  assert.equal(readDecision.kind, 'allow')
  assert.equal(readHarness.state.modelCalls.length, 0)
  assert.equal(readHarness.state.nextCalls, 1)

  const manual = makeHarness({ preset: 'workspace-write' })
  const manualDecision = await manual.handler(makeExec(manual.state, 'bash', { command: 'ls' }), nextOf(manual.state))
  assert.equal(manualDecision.kind, 'allow')
  assert.equal(manual.state.modelCalls.length, 0)
  assert.equal(manual.state.nextCalls, 1)
})

test('reviewReadOnly: true sends reads to the reviewer', async () => {
  const { state, handler } = makeHarness({ reviewReadOnly: true })
  await handler(makeExec(state, 'read', { file_path: 'a.txt' }), nextOf(state))
  assert.equal(state.modelCalls.length, 1)
})

test('a medium denial asks the user when downstream would allow', async () => {
  const { state, handler } = makeHarness({
    text: '{"risk":"medium","decision":"deny","reason":"recursive delete"}',
  })
  const decision = await handler(makeExec(state, 'bash', { command: 'rm -rf src' }), nextOf(state))

  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /recursive delete/)
  assert.equal(state.nextCalls, 1)
})

test('a medium denial is final under approval never', async () => {
  const { state, handler } = makeHarness({
    approval: 'never',
    text: '{"risk":"medium","decision":"deny","reason":"delete"}',
  })
  const decision = await handler(makeExec(state, 'bash', { command: 'rm -rf src' }), nextOf(state))

  assert.equal(decision.kind, 'deny')
  assert.equal(state.nextCalls, 0)
})

test('an unsafe medium allow becomes an ask', async () => {
  const { state, handler } = makeHarness({ text: '{"risk":"medium","decision":"allow"}' })
  const decision = await handler(makeExec(state, 'bash', { command: 'rm -rf src' }), nextOf(state))

  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /medium-risk/)
  assert.equal(state.nextCalls, 1)
})

test('a downstream ask or deny wins over a reviewer denial', async () => {
  const askHarness = makeHarness({
    downstream: { kind: 'ask', reason: 'hard-gate [shell-delete]: needs approval' },
    text: '{"risk":"medium","decision":"deny","reason":"delete"}',
  })
  const ask = await askHarness.handler(makeExec(askHarness.state, 'bash', { command: 'rm -rf src' }), nextOf(askHarness.state))
  assert.equal(ask.kind, 'ask')
  assert.match(ask.reason, /shell-delete/)

  const denyHarness = makeHarness({
    downstream: { kind: 'deny', reason: 'hard-gate [outside-workspace]: no' },
    text: '{"risk":"medium","decision":"deny","reason":"delete"}',
  })
  const deny = await denyHarness.handler(makeExec(denyHarness.state, 'bash', { command: 'rm -rf src' }), nextOf(denyHarness.state))
  assert.equal(deny.kind, 'deny')
  assert.match(deny.reason, /outside-workspace/)
})

test('a reviewer failure fails closed', async () => {
  const { state, handler } = makeHarness({
    streamFactory: () => {
      throw new Error('model down')
    },
  })
  const decision = await handler(makeExec(state, 'bash', { command: 'rm -rf src' }), nextOf(state))

  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /model down/)
  assert.equal(state.nextCalls, 0)
})

test('an unsupported reasoning effort retries with the model default', async () => {
  let first = true
  const { state, handler } = makeHarness({
    reviewReasoningEffort: 'low',
    streamFactory: () => {
      if (first) {
        first = false
        const error = new Error('provider does not support reasoning effort "low"')
        error.code = 'UNSUPPORTED_REASONING_EFFORT'
        throw error
      }
      return textStream('{"risk":"low","decision":"allow"}')
    },
  })
  const decision = await handler(makeExec(state, 'bash', { command: 'ls' }), nextOf(state))

  assert.equal(decision.kind, 'allow')
  assert.equal(state.modelCalls.length, 2)
  assert.equal(state.modelCalls[0].reasoningEffort, 'low')
  assert.equal(state.modelCalls[1].reasoningEffort, undefined)
})

test('run_code is reviewed through its inner calls, not as one blob', async () => {
  const { state, handler } = makeHarness()
  await handler(makeExec(state, 'run_code', { code: 'rmSync("x")' }), nextOf(state))
  assert.equal(state.modelCalls.length, 0)

  await handler(
    makeExec(state, 'bash', { command: 'rm x' }, { parent: { callId: 'c' }, schema: { description: 'Run', parameters: { type: 'object' } } }),
    nextOf(state),
  )
  assert.equal(state.modelCalls.length, 1)
  assert.match(state.modelCalls[0].messages[0].content[0].text, /ptc-inner/)
})

test('cleanup moves Auto sessions to workspace-write and unregisters Auto', async () => {
  const { state } = makeHarness()
  assert.equal(state.autoRegistered, true)
  assert.equal(typeof state.effectDispose, 'function')

  await state.effectDispose()

  assert.equal(state.autoRegistered, false)
  assert.deepEqual(state.setCalls.map((entry) => entry.name), ['workspace-write'])
  assert.equal(state.preset, 'workspace-write')
})

test('a second Auto integration is reported without breaking the gate', () => {
  const { state, handler } = makeHarness({ autoConflict: true })
  assert.equal(handler, undefined)
  assert.equal(state.warnings.length, 1)
  assert.match(state.warnings[0], /already registered/)
  assert.equal(state.effectErrors.length, 0)
})
