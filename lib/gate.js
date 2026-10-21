/**
 * The gate itself: one `tools/pre-execute` decision, one `tools/result`
 * observation, and one monotonic `tools.guard` backstop.
 *
 * Design rules:
 *  - A call with no agent session is not ours to judge; leave it to the host.
 *  - `deny` and `ask` carry a stable rule id so the user can tell a policy
 *    decision from a tool failure.
 *  - Containment and protected paths are enforced twice: once in the waterfall
 *    (rich, async, can explain) and once in a synchronous guard (cannot be
 *    overridden by a later listener).
 *
 * @module dsh-hard-gate/gate
 */

import { stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { createBackupStore } from './backup.js'
import { classifyCommand } from './commands.js'
import {
  canonicalTarget,
  defaultProtectedRoots,
  expandHome,
  isUnder,
  lexicalTarget,
  matchProtected,
  pathKey,
} from './paths.js'
import {
  formatRanges,
  isFullyCovered,
  mergeCoverage,
  missingRanges,
  parseReadFooter,
  ReadTracker,
  readCoverage,
  textOf,
} from './read-tracker.js'
import { MutationBudget } from './state.js'

const DEFAULT_MUTATION_TOOLS = {
  write: 'file_path',
  edit: 'file_path',
  str_replace_editor: 'path',
}

const SHELL_TOOLS = new Set(['pwsh', 'bash', 'shell', 'terminal'])

/** Rules whose real targets live in Git's index rather than on the command line. */
const WORKSPACE_BACKUP_RULES = new Set(['git-clean', 'git-destructive'])

/**
 * A record created by our own successful `write`: the session authored the
 * whole file, so every line is known until the version changes.
 */
const WHOLE_FILE = [[1, Number.MAX_SAFE_INTEGER]]

const PROGRAM_DANGER = /\b(?:rmSync|rm\(|unlinkSync|unlink\(|rmdirSync|truncateSync|fs\.rm|fs\.unlink|fs\.rmdir|writeFileSync|writeFile\(|appendFileSync|appendFile\(|copyFileSync|renameSync|child_process|execSync|spawnSync|exec\(|spawn\()/

export const DEFAULTS = {
  enforceWorkspaceOnly: true,
  extraRoots: [],
  allowPaths: [],
  protectedPaths: [],
  replaceProtectedPaths: false,
  protectedNames: ['.git', '.hg', '.svn'],
  protectedBasenames: ['id_rsa', 'id_ed25519', '.netrc', '.npmrc', '.pypirc', '.git-credentials'],
  allowPartialOverwrite: [],
  requireFullRead: true,
  denyLargeFullRewrite: true,
  largeFileBytes: 5 * 1024 * 1024,
  unknownReadIsComplete: true,
  shellOutsideWorkspace: 'deny',
  regenerable: ['node_modules', 'dist', 'build', 'out', 'target', 'obj', 'coverage', '.cache', '.next', '.nuxt', '.turbo', '.output', 'tmp'],
  maxMutationsPerWindow: 25,
  hardMutationCap: 60,
  windowMs: 10 * 60 * 1000,
  maxWritesPerFile: 5,
  requireEscalationJustification: true,
  allowFileToolEscalation: false,
  askOnProgramMutation: true,
  autoReview: true,
  reviewProvider: '',
  reviewModel: '',
  reviewReasoningEffort: 'low',
  reviewReadOnly: false,
  reviewTimeoutMs: 30_000,
  backupEnabled: true,
  backupDir: '~/.dsh/hard-gate/backups',
  backupMaxBytes: 64 * 1024 * 1024,
  backupMaxFiles: 2000,
  backupRetentionDays: 14,
  backupMaxTotalBytes: 512 * 1024 * 1024,
  backupFailure: 'ask',
  backupEdits: true,
  recycleBin: 'auto',
  recycleBinMaxBytes: 16 * 1024 * 1024,
}

/**
 * Normalize plugin config. Exported so tests exercise the exact defaults the
 * runtime uses.
 */
export function resolveConfig(raw) {
  const input = raw !== null && typeof raw === 'object' ? raw : {}
  const bool = (name, fallback) => (typeof input[name] === 'boolean' ? input[name] : fallback)
  const count = (name, fallback) => (typeof input[name] === 'number' && Number.isFinite(input[name]) && input[name] >= 0 ? input[name] : fallback)
  const list = (name, fallback) => (Array.isArray(input[name]) ? input[name].filter((value) => typeof value === 'string' && value.length > 0) : fallback)

  const extraProtected = list('protectedPaths', [])
  const protectedPaths = input.replaceProtectedPaths === true
    ? extraProtected
    : defaultProtectedRoots().concat(extraProtected)

  const mutationTools = { ...DEFAULT_MUTATION_TOOLS }
  if (input.mutationTools !== null && typeof input.mutationTools === 'object' && !Array.isArray(input.mutationTools)) {
    for (const [tool, field] of Object.entries(input.mutationTools)) {
      if (typeof field === 'string' && field.length > 0) mutationTools[tool] = field
    }
  }

  return {
    enforceWorkspaceOnly: bool('enforceWorkspaceOnly', DEFAULTS.enforceWorkspaceOnly),
    extraRoots: list('extraRoots', []).map(expandHome),
    allowPaths: list('allowPaths', []).map(expandHome),
    protectedPaths: protectedPaths.map(expandHome),
    protectedNames: list('protectedNames', DEFAULTS.protectedNames),
    protectedBasenames: list('protectedBasenames', DEFAULTS.protectedBasenames),
    allowPartialOverwrite: list('allowPartialOverwrite', []),
    requireFullRead: bool('requireFullRead', DEFAULTS.requireFullRead),
    denyLargeFullRewrite: bool('denyLargeFullRewrite', DEFAULTS.denyLargeFullRewrite),
    largeFileBytes: count('largeFileBytes', DEFAULTS.largeFileBytes),
    unknownReadIsComplete: bool('unknownReadIsComplete', DEFAULTS.unknownReadIsComplete),
    shellOutsideWorkspace: input.shellOutsideWorkspace === 'ask' ? 'ask' : 'deny',
    regenerable: list('regenerable', DEFAULTS.regenerable),
    softLimit: count('maxMutationsPerWindow', DEFAULTS.maxMutationsPerWindow),
    hardLimit: count('hardMutationCap', DEFAULTS.hardMutationCap),
    windowMs: count('windowMs', DEFAULTS.windowMs) || DEFAULTS.windowMs,
    perFileLimit: count('maxWritesPerFile', DEFAULTS.maxWritesPerFile),
    requireEscalationJustification: bool('requireEscalationJustification', DEFAULTS.requireEscalationJustification),
    allowFileToolEscalation: bool('allowFileToolEscalation', DEFAULTS.allowFileToolEscalation),
    askOnProgramMutation: bool('askOnProgramMutation', DEFAULTS.askOnProgramMutation),
    autoReview: bool('autoReview', DEFAULTS.autoReview),
    reviewProvider: typeof input.reviewProvider === 'string' ? input.reviewProvider.trim() : DEFAULTS.reviewProvider,
    reviewModel: typeof input.reviewModel === 'string' ? input.reviewModel.trim() : DEFAULTS.reviewModel,
    reviewReasoningEffort: typeof input.reviewReasoningEffort === 'string' ? input.reviewReasoningEffort.trim() : DEFAULTS.reviewReasoningEffort,
    reviewReadOnly: bool('reviewReadOnly', DEFAULTS.reviewReadOnly),
    reviewTimeoutMs: count('reviewTimeoutMs', DEFAULTS.reviewTimeoutMs),
    backupEnabled: bool('backupEnabled', DEFAULTS.backupEnabled),
    backupDir: expandHome(typeof input.backupDir === 'string' && input.backupDir.trim() !== '' ? input.backupDir.trim() : DEFAULTS.backupDir),
    backupMaxBytes: count('backupMaxBytes', DEFAULTS.backupMaxBytes),
    backupMaxFiles: count('backupMaxFiles', DEFAULTS.backupMaxFiles),
    backupRetentionDays: count('backupRetentionDays', DEFAULTS.backupRetentionDays),
    backupMaxTotalBytes: count('backupMaxTotalBytes', DEFAULTS.backupMaxTotalBytes),
    backupFailure: ['ask', 'deny', 'allow'].includes(input.backupFailure) ? input.backupFailure : DEFAULTS.backupFailure,
    backupEdits: bool('backupEdits', DEFAULTS.backupEdits),
    recycleBin: ['auto', 'always', 'never'].includes(input.recycleBin) ? input.recycleBin : DEFAULTS.recycleBin,
    recycleBinMaxBytes: count('recycleBinMaxBytes', DEFAULTS.recycleBinMaxBytes),
    mutationTools,
  }
}

/**
 * Build the gate over a plugin context.
 *
 * @param {{ workingDirectory?: { get(session: object): string }, logger?: object }} ctx
 * @param {object} [rawConfig]
 */
export function createGate(ctx, rawConfig) {
  const config = resolveConfig(rawConfig)
  const knownKeys = new Set(Object.keys(DEFAULTS).concat(['mutationTools']))
  for (const key of Object.keys(rawConfig ?? {})) {
    if (!knownKeys.has(key)) ctx.logger?.warn?.(`hard-gate: unknown config key "${key}" is ignored`)
  }
  const tracker = new ReadTracker()
  const budget = new MutationBudget(config)
  const backups = createBackupStore(ctx, {
    dir: config.backupDir,
    enabled: config.backupEnabled,
    maxBytes: config.backupMaxBytes,
    maxFiles: config.backupMaxFiles,
    retentionDays: config.backupRetentionDays,
    maxTotalBytes: config.backupMaxTotalBytes,
    recycleBin: config.recycleBin,
    recycleBinMaxBytes: config.recycleBinMaxBytes,
    skipDirs: ['.git', '.hg', '.svn'].concat(config.regenerable),
    logger: ctx.logger,
  })
  const protectedRoots = config.protectedPaths.map(pathKey)
    .concat(config.backupEnabled ? [pathKey(config.backupDir)] : [])
  const protectedSegments = new Set(config.protectedNames.map((name) => name.toLowerCase()))
  const protectedBasenames = new Set(config.protectedBasenames.map((name) => name.toLowerCase()))
  const regenerable = new Set(config.regenerable.map((name) => name.toLowerCase()))
  // Harness treats the platform temp root as writable in workspace-write mode;
  // it also lives under protected defaults on Windows (`~/AppData`). Keep that
  // contract instead of making every scratch file a policy violation.
  const tempRoot = tmpdir()
  const allowPartial = config.allowPartialOverwrite.map((source) => {
    try {
      return new RegExp(source, 'i')
    } catch {
      ctx.logger?.warn?.(`hard-gate: ignoring invalid allowPartialOverwrite pattern ${JSON.stringify(source)}`)
      return undefined
    }
  }).filter((pattern) => pattern instanceof RegExp)

  /** Session working directory, or the process directory when the seam is unavailable. */
  function sessionCwd(session) {
    try {
      const value = ctx.workingDirectory?.get?.(session)
      if (typeof value === 'string' && value.length > 0) return value
    } catch {
      // A session without a committed directory is not fatal; fall through.
    }
    return process.cwd()
  }

  /** Writable roots: the session workspace plus configured extras. */
  function rootsFor(session) {
    return [sessionCwd(session)].concat(config.extraRoots)
  }

  function isAllowedPath(absolute) {
    return config.allowPaths.some((root) => isUnder(absolute, root))
  }

  function protectionOf(absolute) {
    // The restore-point store is always protected, even when it lives under the
    // platform temp root (which is otherwise writable by contract).
    if (config.backupEnabled && isUnder(absolute, config.backupDir)) return config.backupDir
    // The platform temp root is writable by contract, so the *root* rules do not
    // apply there. Segment and file-name rules (`.git`, `id_rsa`, …) still do.
    const rules = isUnder(absolute, tempRoot)
      ? { roots: [], segments: protectedSegments, basenames: protectedBasenames }
      : { roots: protectedRoots, segments: protectedSegments, basenames: protectedBasenames }
    return matchProtected(pathKey(absolute), rules)
  }

  function deny(rule, reason) {
    return { kind: 'deny', reason: `hard-gate [${rule}]: ${reason}` }
  }

  function ask(rule, reason) {
    return { kind: 'ask', reason: `hard-gate [${rule}]: ${reason}`, displayReason: `hard-gate: ${rule}` }
  }

  function record(decision, tool) {
    ctx.logger?.info?.(`hard-gate: ${decision.kind} on tool "${tool}" — ${decision.reason ?? 'blocked'}`)
  }

  /** Tell the human (and the model) that a recovery copy exists before they approve. */
  function withBackup(decision, backup) {
    if (backup?.id !== undefined) {
      decision.reason = `${decision.reason} Restore point ${backup.id} is available (${backup.files} file(s)).`
    }
    return decision
  }

  /**
   * Take a restore point before an allowed/asked mutation. A backup failure is
   * itself a policy decision: the operation may proceed only under the
   * configured `backupFailure` mode, never silently without a copy.
   */
  async function ensureBackup(exec, session, targets, meta) {
    if (!config.backupEnabled) return undefined
    if (!Array.isArray(targets) || targets.length === 0) return undefined
    try {
      const result = await backups.backup(targets, {
        tool: exec.name,
        rule: meta.rule,
        cwd: sessionCwd(session),
        roots: rootsFor(session),
        session,
        bin: meta.bin,
      })
      if (result.empty === true) return undefined
      ctx.logger?.info?.(`hard-gate: restore point ${result.id} for "${exec.name}" (${result.files} file(s), ${result.bytes} bytes) at ${result.zip}`)
      return result
    } catch (error) {
      const detail = error?.message ?? String(error)
      ctx.logger?.warn?.(`hard-gate: restore point failed before "${exec.name}": ${detail}`)
      if (config.backupFailure === 'deny') {
        return deny(
          'backup-failed',
          `refusing "${exec.name}" because a restore point could not be created (${detail}) and hard-gate.backupFailure is "deny".`,
        )
      }
      if (config.backupFailure === 'ask') {
        return ask(
          'backup-failed',
          `a restore point could not be created before "${exec.name}" (${detail}). Continue without a recovery copy?`,
        )
      }
      return undefined
    }
  }

  // ── tools/pre-execute ───────────────────────────────────────────────────────

  async function preExecute(exec, next) {
    let decision
    try {
      decision = await evaluate(exec)
    } catch (error) {
      // Fail open on an internal error, but say so: a broken gate must not look
      // like a policy denial, and it must not silently become the sandbox.
      ctx.logger?.warn?.(`hard-gate: evaluation failed for tool "${exec?.name}": ${error?.message ?? error}`)
      return next()
    }
    if (decision === undefined) return next()
    record(decision, exec?.name)
    return decision
  }

  async function evaluate(exec) {
    if (exec === null || typeof exec !== 'object' || typeof exec.name !== 'string') return undefined
    const session = exec.agent?.session
    if (session === undefined) return undefined
    const args = isRecord(exec.arguments) ? exec.arguments : {}

    const escalation = checkEscalation(exec.name, args)
    if (escalation !== undefined) return escalation

    if (SHELL_TOOLS.has(exec.name)) return evaluateShell(exec, args, session)

    const pathField = config.mutationTools[exec.name]
    if (typeof pathField === 'string') return evaluateMutation(exec, args, pathField, session)

    if (typeof args.code === 'string' && config.askOnProgramMutation && PROGRAM_DANGER.test(args.code)) {
      return ask(
        'program-fs-mutation',
        'the program performs filesystem or process mutation directly, so its targets cannot be checked before it runs.',
      )
    }

    return undefined
  }

  function checkEscalation(tool, args) {
    if (args.sandbox_permissions === undefined) return undefined
    const isFileTool = typeof config.mutationTools[tool] === 'string'
    if (isFileTool && !config.allowFileToolEscalation) {
      return deny(
        'file-tool-escalation',
        `file tools may not request "${String(args.sandbox_permissions)}". Writes are limited to the workspace and need no wider mode.`,
      )
    }
    if (config.requireEscalationJustification) {
      const justification = typeof args.justification === 'string' ? args.justification.trim() : ''
      if (justification.length < 12) {
        return deny(
          'missing-justification',
          `a sandbox escalation needs a concrete justification of at least 12 characters (got ${justification.length}).`,
        )
      }
    }
    return undefined
  }

  async function evaluateShell(exec, args, session) {
    const command = args.command
    if (typeof command !== 'string' || command.trim() === '') return undefined

    const workspace = sessionCwd(session)
    const cwd = typeof args.workdir === 'string' && args.workdir.trim() !== ''
      ? lexicalTarget(workspace, args.workdir)
      : workspace

    const result = classifyCommand(command, {
      cwd,
      workspaceRoots: rootsFor(session),
      allowPaths: config.allowPaths,
      regenerable,
      outsidePolicy: config.shellOutsideWorkspace,
    })

    if (result.level === 'deny') return deny(result.rule, result.reason ?? 'blocked')
    let verdict = 'ok'
    if (result.destructive) {
      verdict = budget.charge(session, `shell:${result.rule}`)
      if (verdict === 'deny') return deny('mutation-budget', budgetMessage(session, 'shell command'))
    }
    // Deletes and overwrites both get a restore point. The budget may still ask
    // afterwards, so take the copy before the approval prompt: if the user says
    // yes, the safety net must already exist.
    let backup
    if (result.destructive || result.overwrites) {
      const targets = WORKSPACE_BACKUP_RULES.has(result.rule) ? [sessionCwd(session)] : result.targets
      backup = await ensureBackup(exec, session, targets, {
        rule: `shell:${result.rule}`,
        bin: true,
      })
      if (backup?.kind === 'deny') return backup
    }
    if (verdict === 'ask' && result.level === 'allow') {
      if (backup?.kind === 'ask') return backup
      return withBackup(ask('mutation-budget', budgetMessage(session, 'shell command')), backup)
    }
    if (result.level === 'ask') {
      const decision = ask(result.rule, result.reason ?? 'needs confirmation')
      if (backup?.kind === 'ask') {
        decision.reason = `${decision.reason} Additionally, ${backup.reason}`
        return decision
      }
      return withBackup(decision, backup)
    }
    if (backup?.kind === 'ask') return backup
    return undefined
  }

  async function evaluateMutation(exec, args, pathField, session) {
    if (!isMutationCall(exec, args)) return undefined

    const raw = args[pathField]
    if (typeof raw !== 'string' || raw.trim() === '') return undefined

    const absolute = await canonicalTarget(sessionCwd(session), raw)

    const hit = protectionOf(absolute)
    if (hit !== undefined) {
      return deny(
        'protected-path',
        `"${raw}" resolves to "${absolute}", inside the protected path "${hit}". This stays blocked in every permission mode.`,
      )
    }

    if (config.enforceWorkspaceOnly && !isAllowedPath(absolute)) {
      const roots = rootsFor(session)
      if (!roots.some((root) => isUnder(absolute, root))) {
        return deny(
          'outside-workspace',
          `"${raw}" resolves to "${absolute}", outside the session workspace (${roots.join(', ')}). Hard-gate keeps writes inside the workspace even in Full access.`,
        )
      }
    }

    if (exec.name === 'write' && config.requireFullRead && !matchesAllowPartial(absolute)) {
      const view = await checkFullView(exec, session, absolute, raw)
      if (view !== undefined) return view
    }

    const verdict = budget.charge(session, pathKey(absolute))
    if (verdict === 'deny') return deny('mutation-budget', budgetMessage(session, raw))

    let backup
    if (exec.name === 'write' || config.backupEdits) {
      backup = await ensureBackup(exec, session, [absolute], {
        rule: `file:${exec.name}`,
        bin: exec.name === 'write',
      })
      if (backup?.kind !== undefined) return backup
    }

    if (verdict === 'ask') return withBackup(ask('mutation-budget', budgetMessage(session, raw)), backup)
    return undefined
  }

  function matchesAllowPartial(absolute) {
    return allowPartial.some((pattern) => pattern.test(absolute))
  }

  /**
   * The full-view rule: a whole-file replacement requires that the session read
   * this exact version to EOF. A windowed read is not enough — that is precisely
   * the read that loses the middle of the file.
   */
  async function checkFullView(exec, session, absolute, raw) {
    let info
    try {
      info = await stat(absolute)
    } catch {
      return undefined // Creating a new file: nothing to lose.
    }
    if (!info.isFile() || info.size === 0) return undefined

    if (config.denyLargeFullRewrite && info.size > config.largeFileBytes) {
      return deny(
        'large-full-rewrite',
        `"${raw}" is ${info.size} bytes; replacing it wholesale is not safe at this size. Use targeted edits, or raise hard-gate.largeFileBytes.`,
      )
    }

    const seen = tracker.get(session, pathKey(absolute))
    if (seen === undefined) {
      return deny(
        'full-view-missing',
        `refusing to replace all of "${raw}" (${info.size} bytes): this session has not read it. Read the file first, or use targeted edits.`,
      )
    }
    if (seen.complete !== true) {
      const missing = missingRanges(seen.ranges, seen.total)
      const detail = missing.length > 0 && seen.total !== undefined
        ? `your reads never covered ${formatRanges(missing)} of ${seen.total}`
        : 'only part of the file was read'
      return deny(
        'full-view-partial',
        `refusing to replace all of "${raw}": ${detail}, so writing it back would drop the unseen lines. Read the missing lines (or use edit) first.`,
      )
    }
    if (seen.mtimeMs !== undefined && seen.size !== undefined) {
      if (seen.size !== info.size || Math.abs(seen.mtimeMs - info.mtimeMs) > 1) {
        return deny(
          'full-view-stale',
          `refusing to replace all of "${raw}": it changed on disk after your last read. Read it again first.`,
        )
      }
    }
    return undefined
  }

  function budgetMessage(session, target) {
    const snapshot = budget.snapshot(session)
    const count = snapshot?.count ?? 0
    const minutes = Math.round(config.windowMs / 60000)
    return `this session has attempted ${count} file mutations in ${minutes} minutes (last: "${target}"). Mass edits need a human decision; split the work or raise hard-gate.maxMutationsPerWindow.`
  }

  // ── tools/result ────────────────────────────────────────────────────────────

  async function observe(exec, result) {
    const session = exec?.agent?.session
    if (session === undefined) return
    try {
      if (exec.name === 'read') return await recordRead(exec, result, session)
      if (exec.name === 'write' || exec.name === 'edit') return await refreshMutation(exec, result, session)
    } catch (error) {
      ctx.logger?.warn?.(`hard-gate: observation failed for tool "${exec.name}": ${error?.message ?? error}`)
    }
  }

  async function recordRead(exec, result, session) {
    const args = isRecord(exec.arguments) ? exec.arguments : {}
    if (typeof args.file_path !== 'string' || args.file_path.trim() === '') return
    if (isErrorResult(result)) return

    const coverage = readCoverage(result) ?? parseReadFooter(textOf(result))
    const absolute = await canonicalTarget(sessionCwd(session), args.file_path)
    const key = pathKey(absolute)
    const info = await safeStat(absolute)
    const previous = tracker.get(session, key)

    // Ranges recorded against an older version describe a different file.
    const sameVersion = previous !== undefined
      && info !== undefined
      && previous.size === info.size
      && typeof previous.mtimeMs === 'number'
      && Math.abs(previous.mtimeMs - info.mtimeMs) <= 1
    const priorComplete = sameVersion && previous.complete === true
    let ranges = sameVersion && Array.isArray(previous.ranges) ? previous.ranges : []
    if (coverage !== undefined) ranges = mergeCoverage(ranges, coverage.start, coverage.end)
    const total = coverage?.total ?? (sameVersion ? previous.total : undefined)

    tracker.record(session, key, {
      complete: priorComplete
        || (coverage === undefined && config.unknownReadIsComplete)
        || isFullyCovered(ranges, total),
      total,
      ranges,
      start: coverage?.start ?? previous?.start,
      end: coverage?.end ?? previous?.end,
      mtimeMs: info?.mtimeMs,
      size: info?.size,
      at: Date.now(),
    })
  }

  /**
   * Keep the record in step with our own successful writes:
   *  - `write` authors the whole file, so the session now knows it completely;
   *  - `edit` preserves whatever completeness the read had, only the version moves.
   */
  async function refreshMutation(exec, result, session) {
    if (isErrorResult(result)) return
    const args = isRecord(exec.arguments) ? exec.arguments : {}
    const pathField = config.mutationTools[exec.name]
    if (typeof pathField !== 'string') return
    const raw = args[pathField]
    if (typeof raw !== 'string' || raw.trim() === '') return

    const absolute = await canonicalTarget(sessionCwd(session), raw)
    const key = pathKey(absolute)
    const info = await safeStat(absolute)
    const previous = tracker.get(session, key)

    if (exec.name === 'write') {
      tracker.record(session, key, {
        complete: true,
        ranges: WHOLE_FILE,
        mtimeMs: info?.mtimeMs,
        size: info?.size,
        at: Date.now(),
      })
    } else if (previous !== undefined) {
      tracker.record(session, key, { ...previous, mtimeMs: info?.mtimeMs, size: info?.size, at: Date.now() })
    }
  }

  // ── tools.guard (monotonic backstop) ────────────────────────────────────────

  /**
   * Synchronous, deny-only, runs after the waterfall. A later listener cannot
   * approve its way past the two invariants that must hold in every mode:
   * protected paths, and (when enabled) workspace containment.
   */
  function hardGuard(exec) {
    try {
      if (exec === null || typeof exec !== 'object' || !exec.agent?.session) return undefined
      const pathField = config.mutationTools[exec.name]
      if (typeof pathField !== 'string') return undefined
      const args = isRecord(exec.arguments) ? exec.arguments : {}
      if (!isMutationCall(exec, args)) return undefined
      const raw = args[pathField]
      if (typeof raw !== 'string' || raw.trim() === '') return undefined

      const absolute = lexicalTarget(sessionCwd(exec.agent.session), raw)
      const hit = protectionOf(absolute)
      if (hit !== undefined) return `hard-gate [guard/protected-path]: "${raw}" targets the protected path "${hit}".`

      if (config.enforceWorkspaceOnly && !isAllowedPath(absolute)) {
        const roots = rootsFor(exec.agent.session)
        if (!roots.some((root) => isUnder(absolute, root))) {
          return `hard-gate [guard/outside-workspace]: "${raw}" is outside the session workspace (${roots.join(', ')}).`
        }
      }
      return undefined
    } catch {
      // Fail open on an unexpected error, matching preExecute: the invariants
      // above are computed without I/O, so a throw here would be a logic bug,
      // and turning that into a blanket deny would brick every write.
      return undefined
    }
  }

  function dispose() {
    tracker.clear()
    budget.clear()
    void backups.dispose()
  }

  return { preExecute, observe, hardGuard, dispose, config }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * Whether a tool call can change an existing file. `str_replace_editor view`
 * only reads, so neither the waterfall nor the guard may judge its path.
 */
function isMutationCall(exec, args) {
  if (exec.name !== 'str_replace_editor') return true
  return args.command === 'create' || args.command === 'str_replace' || args.command === 'insert'
}

function isErrorResult(result) {
  if (result === null || typeof result !== 'object') return true
  if (result.isError === true) return true
  if (result.ok === false && result.content === undefined) return true
  return false
}

async function safeStat(absolute) {
  try {
    const info = await stat(absolute)
    return info.isFile() ? { mtimeMs: info.mtimeMs, size: info.size } : undefined
  } catch {
    return undefined
  }
}
