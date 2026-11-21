/**
 * dsh-hard-gate — stricter permission review and a workspace sandbox for
 * DeepSeek Harness that keeps working in `danger-full-access`.
 *
 * The plugin registers three things and no service:
 *  - a prepended `tools/pre-execute` listener that can deny or ask;
 *  - a `tools/result` observer that learns whether a read reached EOF;
 *  - a `tools.guard` backstop that nothing downstream can override.
 *
 * When the host exposes the LLM and permission services, it also installs a
 * context-free Auto reviewer that sees only the pending action.
 *
 * @module dsh-hard-gate
 */

import { createRequire } from 'node:module'
import { installAutoReview } from './auto-review.js'
import { DEFAULTS, createGate } from './gate.js'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'hard-gate'

/** Services the gate reads. */
export const inject = ['tools', 'workingDirectory']

const require = createRequire(import.meta.url)

/**
 * A linked local directory makes bare imports resolve from the checkout, not
 * from the profile, so `@deepseek-ai/schemastery` may be absent at runtime (the
 * CommonJS build is loaded synchronously; `NODE_PATH` can supply it). The schema
 * is a settings-UI convenience — the gate validates config itself — so a missing
 * schema degrades to "no settings form", never to "no gate".
 */
const schema = loadSchema()

/** Config schema, present only when schemastery is resolvable. */
export const Config = schema === undefined ? undefined : buildConfig(schema)

/**
 * @param {object} ctx - plugin context.
 * @param {object} config - plugin config (validated when the schema is available).
 */
export function apply(ctx, config) {
  const gate = createGate(ctx, config)

  ctx.effect(() => () => {
    gate.dispose()
  }, 'hard-gate state teardown')

  // Prepend: our deny must be seen before an LLM reviewer can approve the call.
  ctx.on('tools/pre-execute', (exec, next) => gate.preExecute(exec, next), { prepend: true })

  // The context-free Auto reviewer is optional: it activates only when the
  // host has the LLM and permission services. It runs before the gate and
  // always calls through, so it can add friction but never bypass the gate.
  installAutoReview(ctx, gate.config)

  ctx.on('tools/result', (exec, result) => gate.observe(exec, result))

  if (typeof ctx.tools?.guard === 'function') {
    const disposeGuard = ctx.tools.guard((exec) => gate.hardGuard(exec))
    ctx.effect(() => () => {
      try {
        disposeGuard?.()
      } catch {
        // The tools service may already be gone during teardown.
      }
    }, 'hard-gate guard teardown')
  } else {
    ctx.logger?.warn?.('hard-gate: tools.guard is unavailable; the monotonic backstop is disabled')
  }
}

/** Load schemastery when it is resolvable; `undefined` otherwise. */
function loadSchema() {
  try {
    return require('@deepseek-ai/schemastery')
  } catch {
    return undefined
  }
}

function buildConfig(schema) {
  return schema.object({
    enforceWorkspaceOnly: schema.boolean().default(DEFAULTS.enforceWorkspaceOnly)
      .description('Deny file-tool writes outside the session workspace even in Full access.'),
    extraRoots: schema.array(schema.string()).default([])
      .description('Additional writable roots, absolute or `~`-relative.'),
    allowPaths: schema.array(schema.string()).default([])
      .description('Roots exempt from workspace containment (protected paths still win).'),
    protectedPaths: schema.array(schema.string()).default([])
      .description('Extra protected roots, added to the platform defaults unless replaceProtectedPaths is true.'),
    replaceProtectedPaths: schema.boolean().default(false)
      .description('Use protectedPaths as the complete protected set, dropping the platform defaults.'),
    protectedNames: schema.array(schema.string()).default(DEFAULTS.protectedNames)
      .description('Path segments that may never be written by a file tool.'),
    protectedBasenames: schema.array(schema.string()).default(DEFAULTS.protectedBasenames)
      .description('File names that may never be written by a file tool.'),
    allowPartialOverwrite: schema.array(schema.string()).default([])
      .description('Regex sources; matching paths skip the full-view overwrite rule.'),
    requireFullRead: schema.boolean().default(DEFAULTS.requireFullRead)
      .description('Require a read to EOF before a whole-file `write` may replace an existing file.'),
    denyLargeFullRewrite: schema.boolean().default(DEFAULTS.denyLargeFullRewrite)
      .description('Refuse whole-file replacement of files above largeFileBytes.'),
    largeFileBytes: schema.number().default(DEFAULTS.largeFileBytes)
      .description('Size threshold for denyLargeFullRewrite.'),
    unknownReadIsComplete: schema.boolean().default(DEFAULTS.unknownReadIsComplete)
      .description('Treat a read result without a recognised footer as complete (fail-open).'),
    shellOutsideWorkspace: schema.union([schema.const('deny'), schema.const('ask')]).default(DEFAULTS.shellOutsideWorkspace)
      .description('Decision for a destructive shell command with an explicit target outside the workspace.'),
    regenerable: schema.array(schema.string()).default(DEFAULTS.regenerable)
      .description('Directory names that may be deleted recursively without asking.'),
    maxMutationsPerWindow: schema.number().default(DEFAULTS.maxMutationsPerWindow)
      .description('Soft mutation budget per window; 0 disables it.'),
    hardMutationCap: schema.number().default(DEFAULTS.hardMutationCap)
      .description('Hard mutation cap per window; 0 disables it.'),
    windowMs: schema.number().default(DEFAULTS.windowMs)
      .description('Budget window length in milliseconds.'),
    maxWritesPerFile: schema.number().default(DEFAULTS.maxWritesPerFile)
      .description('Writes to one file per window before the gate asks; 0 disables it.'),
    requireEscalationJustification: schema.boolean().default(DEFAULTS.requireEscalationJustification)
      .description('Require a substantive justification on any sandbox escalation.'),
    allowFileToolEscalation: schema.boolean().default(DEFAULTS.allowFileToolEscalation)
      .description('Permit file tools to request a wider sandbox mode.'),
    askOnProgramMutation: schema.boolean().default(DEFAULTS.askOnProgramMutation)
      .description('Ask before a programmatic tool call whose code mutates the filesystem directly.'),
    autoReview: schema.boolean().default(DEFAULTS.autoReview)
      .description('Offer the Auto preset and review each call with a model that sees only the pending action.'),
    reviewProvider: schema.string().default(DEFAULTS.reviewProvider)
      .description('Optional provider for the Auto reviewer; set together with reviewModel, empty uses the session route.'),
    reviewModel: schema.string().default(DEFAULTS.reviewModel)
      .description('Optional model for the Auto reviewer; set together with reviewProvider.'),
    reviewReasoningEffort: schema.string().default(DEFAULTS.reviewReasoningEffort)
      .description('Reasoning effort for the reviewer; empty uses the model default.'),
    reviewReadOnly: schema.boolean().default(DEFAULTS.reviewReadOnly)
      .description('Review read-only tools too; false skips the model call for reads, searches, and lists.'),
    reviewTimeoutMs: schema.number().default(DEFAULTS.reviewTimeoutMs)
      .description('Reviewer timeout; a timeout fails closed. 0 disables it.'),
    backupEnabled: schema.boolean().default(DEFAULTS.backupEnabled)
      .description('Zip destructive targets into a restore point before a write, edit, delete, or overwrite runs.'),
    backupDir: schema.string().default(DEFAULTS.backupDir)
      .description('Restore-point store; keep it outside the workspace.'),
    backupMaxBytes: schema.number().default(DEFAULTS.backupMaxBytes)
      .description('Largest uncompressed restore point; larger operations become an explicit ask.'),
    backupMaxFiles: schema.number().default(DEFAULTS.backupMaxFiles)
      .description('Largest number of files in one restore point.'),
    backupRetentionDays: schema.number().default(DEFAULTS.backupRetentionDays)
      .description('Delete restore points older than this many days; 0 keeps them.'),
    backupMaxTotalBytes: schema.number().default(DEFAULTS.backupMaxTotalBytes)
      .description('Total restore-point store budget; oldest archives are pruned first.'),
    backupFailure: schema.union([schema.const('ask'), schema.const('deny'), schema.const('allow')]).default(DEFAULTS.backupFailure)
      .description('What to do when a restore point cannot be created.'),
    backupEdits: schema.boolean().default(DEFAULTS.backupEdits)
      .description('Take a restore point before targeted `edit` / `str_replace_editor` changes too.'),
    recycleBin: schema.union([schema.const('auto'), schema.const('always'), schema.const('never')]).default(DEFAULTS.recycleBin)
      .description('Send a copy of each restore-point zip to the Windows Recycle Bin (`auto`: Windows only).'),
    recycleBinMaxBytes: schema.number().default(DEFAULTS.recycleBinMaxBytes)
      .description('Largest archive copied to the Recycle Bin; 0 disables the copy.'),
    mutationTools: schema.dict(schema.string()).default({})
      .description('Extra tool name to path-argument map, e.g. {"apply_patch": "path"}.'),
    ruleSeverity: schema.dict(schema.string()).default({})
      .description('Per-rule severity override by rule id: "deny", "ask", "allow" or "off" (skip). E.g. {"git-destructive": "deny", "publish": "off"}.'),
  })
}
