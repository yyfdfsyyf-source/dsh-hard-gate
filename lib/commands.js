/**
 * Shell command classification for the hard gate.
 *
 * The classifier is deliberately conservative and purely lexical: it never
 * executes anything and never trusts the command's own flags. It answers three
 * questions, in order: is this command unconditionally forbidden, does it remove
 * or overwrite an explicit target outside the workspace, and does it delete at a
 * scale that needs a human decision (recursive, wildcard, or piped)?
 *
 * @module dsh-hard-gate/commands
 */

import { isAbsolute, resolve } from 'node:path'
import { homedir } from 'node:os'
import { expandHome, isUnder, relativeSegments, unquote } from './paths.js'

/** Verbs whose normal use removes an object. */
const DELETE_VERB = /\b(?:remove-item|ri|rm|rmdir|rd|del|erase|unlink|shred)\b/i

/** Verbs whose normal use writes or moves over an existing object. */
const WRITE_VERB = /\b(?:remove-item|ri|rm|rmdir|rd|del|erase|move-item|mv|copy-item|cp|rename-item|ren|set-content|add-content|out-file|new-item|ni|clear-content|clc|robocopy|xcopy|tee-object|tee|truncate)\b/i

/** A delete driven by a predicate rather than an explicit path list. */
const FIND_DELETE = /\bfind\b[^\n;|&]*(?:-delete\b|-exec(?:dir)?\s+(?:rm|unlink|shred)\b)/i

/** `rsync --delete*` removes destination files that are absent from the source. */
const RSYNC_DELETE = /\brsync\b[^\n;|&]*--delete/i

/** Recursive switch in either PowerShell or POSIX spelling. */
const RECURSIVE = /(?:\s-recurse\b|(?:^|\s)-[a-z]*r[a-z]*(?=\s|$)|(?:^|\s)\/s\b|\brm\s+-[a-z]*r)/i

/**
 * Git global options that may sit between `git` and its subcommand. `-C <dir>`
 * and `--git-dir=<dir>` are the common ways to aim Git at another repository;
 * ignoring them let `git -C <dir> clean -fdx` slip past every Git rule.
 */
const GIT_GLOBAL = String.raw`(?:(?:-C|-c|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix)\s+(?:"[^"]*"|'[^']*'|\S+)|--[a-z][a-z-]*(?:=\S+)?|-[A-Za-z])\s+`
const GIT_PREFIX = String.raw`\bgit(?:\.exe)?\s+(?:${GIT_GLOBAL})*`
const GIT_CLEAN = new RegExp(String.raw`${GIT_PREFIX}clean\b([^\n;|&]*)`, 'i')
const GIT_DESTRUCTIVE = new RegExp(
  String.raw`${GIT_PREFIX}(?:reset\s+--hard|checkout\s+(?:--\s+)?\.|restore\s+\.|restore\s+--staged\s+\.|stash\s+(?:drop|clear)|branch\s+-D|push\s+[^\n;|&]*--force(?!-with-lease))`,
  'i',
)

/** A target at a filesystem root, a drive root, or the home directory. */
const CATASTROPHIC = /(?:^|[\s"'`=])(?:[a-z]:[\\/]?(?=[\s"'`;|&)]|$)|\\\\[^\\\s"'`]+\\(?:[^\\\s"'`]+)?(?=[\s"'`;|&)]|$)|~(?=[\s"'`;|&)]|$)|\$home(?=[\s"'`;|&)]|$)|\$env:(?:userprofile|home)(?=[\s"'`;|&)]|$)|(?:\/(?:\*)?)(?=[\s"'`;|&)]|$))/i

/** Tokens that are never path operands. */
const NON_OPERANDS = new Set([
  'remove-item', 'ri', 'rm', 'rmdir', 'rd', 'del', 'erase',
  'move-item', 'mv', 'copy-item', 'cp', 'rename-item', 'ren',
  'set-content', 'add-content', 'out-file', 'new-item', 'ni',
  'clear-content', 'clc', 'robocopy', 'xcopy', 'tee-object', 'tee',
  'get-childitem', 'gci', 'ls', 'dir', 'where-object', 'foreach-object',
  'select-object', 'sort-object', 'measure-object', 'format-table',
  'out-string', 'write-output', 'write-host',
  '$null', '$true', '$false',
])

/** Rules that deny regardless of where the command points. */
const DENY_RULES = [
  {
    id: 'disk-destructive',
    test: (c) => /\b(?:format-volume|clear-disk|initialize-disk|diskpart|remove-partition|resize-partition|repair-volume|cipher\s+\/w|vssadmin\s+(?:delete|resize)|wbadmin\s+delete|bcdedit|bootrec)\b|(?:^|[;&|]\s*)\s*format\s+[a-z]:/i.test(c),
    why: 'it destroys or rewrites disks, partitions, boot records, or shadow copies',
    hint: 'disk-level maintenance is not a coding task; ask the user to run it themselves.',
  },
  {
    id: 'security-tamper',
    test: (c) => /(?:reg(?:\.exe)?\s+delete\s+hk(?:lm|cu)|sc(?:\.exe)?\s+delete|net\s+user\s+\S+\s+\/delete|takeown\s+\/|icacls\s+\S+\s+\/(?:reset|deny|remove)|set-mppreference|add-mppreference|disable-(?:windowsdefender|realtimemonitoring|antivirus)|netsh\s+advfirewall\s+set\s+\S+\s+state\s+off|set-executionpolicy|unregister-scheduledtask|schtasks\s+\/delete)/i.test(c),
    why: 'it changes security controls (Defender, firewall, ACLs, services, tasks, execution policy)',
    hint: 'security configuration is the user\'s decision, not part of a coding task.',
  },
  {
    id: 'git-clean-x',
    test: (c) => {
      const flags = gitCleanFlags(c)
      return flags !== undefined && flags.has('f') && flags.has('x') && !flags.has('n')
    },
    why: '`git clean -x` permanently deletes untracked AND ignored files (build output, local config, .env)',
    hint: 'run `git clean -ndx` first to list exactly what would be deleted, then remove specific paths.',
  },
  {
    id: 'power-state',
    test: (c) => /(?:^|[;&|]\s*)\s*(?:shutdown|stop-computer|restart-computer|logoff)\b/i.test(c),
    why: 'it shuts down, restarts, or logs off the machine',
  },
  {
    id: 'raw-device',
    test: (c) => /(?:\\\\\.\\[a-z]:|\bdd\s+if=|of=\/dev\/(?:sd|nvme|hd)|\bmkfs(?:\.\w+)?\b|\bfdisk\b)/i.test(c),
    why: 'it writes to a raw device or reformats a filesystem',
  },
]

/** Rules that require a one-shot human decision. */
const ASK_RULES = [
  {
    id: 'git-clean',
    test: (c) => {
      const flags = gitCleanFlags(c)
      return flags !== undefined && flags.has('f') && !flags.has('x') && !flags.has('n')
    },
    why: '`git clean` deletes untracked files without any recovery path',
    hint: 'run `git clean -nd` first to list exactly what would be deleted.',
  },
  {
    id: 'git-destructive',
    test: (c) => GIT_DESTRUCTIVE.test(c),
    why: 'it discards or rewrites Git history or uncommitted work',
  },
  {
    id: 'mirror-copy',
    test: (c) => /\brobocopy\b[^\n;|&]*\/(?:mir|purge)\b/i.test(c),
    why: '`robocopy /MIR` deletes every destination file that is absent from the source',
  },
  {
    id: 'inline-code',
    test: (c) => /\b(?:node|nodejs)\s+(?:-e|--eval)\b|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b|-encodedcommand\b|\bcmd(?:\.exe)?\s+\/c\b/i.test(c),
    why: 'inline interpreter code hides its real file operations from the gate',
    hint: 'write the program to a file in the workspace and run that file instead.',
  },
  {
    id: 'download-execute',
    test: (c) => /(?:invoke-webrequest|invoke-restmethod|iwr|irm|curl|wget)[^\n;|&]*\|[^\n]*\b(?:iex|invoke-expression|sh|bash)\b|(?:^|[;&|]\s*)iex\s*\(/i.test(c),
    why: 'it downloads and executes remote code',
  },
  {
    id: 'publish',
    test: (c) => /\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bdotnet\s+nuget\s+push\b|\bcargo\s+publish\b/i.test(c),
    why: 'it publishes artifacts to a remote registry',
  },
  {
    id: 'archive-force',
    test: (c) => /\b(?:expand-archive|unzip|tar)\b[^\n;|&]*(?:-force\b|-o\b|--overwrite\b)/i.test(c),
    why: 'it extracts an archive over existing files',
  },
  {
    id: 'elevate',
    test: (c) => /-verb\s+runas\b|\bsudo\b|\bgsudo\b/i.test(c),
    why: 'it requests elevation',
  },
]

/**
 * Extract `git clean`'s single-dash flag cluster. Combined flags (`-fdx`) are
 * split, and `--dry-run` is normalized to `n`, so the dry-run check is exact
 * rather than a substring guess.
 *
 * @param {string} command
 * @returns {Set<string> | undefined} `undefined` when the command is not `git clean`.
 */
function gitCleanFlags(command) {
  const match = GIT_CLEAN.exec(command)
  if (match === null) return undefined
  const flags = new Set()
  for (const token of match[1].trim().split(/\s+/)) {
    if (token === '') continue
    if (token === '--dry-run') {
      flags.add('n')
      continue
    }
    if (!token.startsWith('-') || token.startsWith('--')) continue
    for (const character of token.slice(1)) flags.add(character.toLowerCase())
  }
  return flags
}

/**
 * @typedef {object} Classification
 * @property {'allow' | 'ask' | 'deny'} level
 * @property {string} rule - stable rule id for logs and tests.
 * @property {string} [reason] - model-facing explanation.
 * @property {boolean} destructive - whether the command can remove data.
 * @property {boolean} overwrites - whether the command can replace existing data.
 * @property {string[]} targets - resolved path operands, for pre-run backups.
 */

/**
 * Classify one shell command.
 *
 * @param {string} command - the raw command string the model asked to run.
 * @param {object} options
 * @param {string} options.cwd - effective working directory.
 * @param {string[]} options.workspaceRoots - writable roots (session cwd + extras).
 * @param {string[]} [options.allowPaths] - extra roots exempt from containment.
 * @param {Set<string>} [options.regenerable] - lower-case directory names that
 *   may be deleted recursively without asking (build output, caches).
 * @param {'deny' | 'ask'} [options.outsidePolicy] - decision for a destructive
 *   command that targets an explicit path outside the workspace.
 * @returns {Classification}
 */
export function classifyCommand(command, options) {
  const cmd = String(command ?? '').trim()
  const opts = options ?? {}
  if (cmd === '') return make('allow', 'empty', false)

  for (const rule of DENY_RULES) {
    if (rule.test(cmd)) return make('deny', rule.id, true, rule.why, rule.hint)
  }

  // Resolved operands are also the backup targets. Lexical resolution is
  // enough here: the backup layer skips paths that do not exist.
  const operands = operandsOf(cmd, opts.cwd)
  const targets = operands.filter((operand) => typeof operand.absolute === 'string').map((operand) => operand.absolute)

  for (const rule of ASK_RULES) {
    if (rule.test(cmd)) return make('ask', rule.id, true, rule.why, rule.hint, targets, true)
  }

  const removal = DELETE_VERB.test(cmd) || FIND_DELETE.test(cmd) || RSYNC_DELETE.test(cmd)
  const overwrite = WRITE_VERB.test(cmd) || hasRedirect(cmd)
  if (!removal && !overwrite) return make('allow', 'default', false)

  const roots = Array.isArray(opts.workspaceRoots) ? opts.workspaceRoots : [opts.cwd]
  const allowPaths = Array.isArray(opts.allowPaths) ? opts.allowPaths : []
  const regenerable = opts.regenerable instanceof Set ? opts.regenerable : new Set()

  if (CATASTROPHIC.test(cmd)) {
    return make(
      'deny',
      'catastrophic-target',
      true,
      'it targets a filesystem root, a drive root, or your home directory',
      'name the specific project path you mean; roots are never acceptable targets.',
    )
  }

  const outside = []
  const unresolved = []
  let allRegenerable = operands.length > 0

  for (const operand of operands) {
    if (operand.unresolved) {
      unresolved.push(operand.text)
      allRegenerable = false
      continue
    }
    const absolute = operand.absolute
    if (!insideAny(absolute, roots.concat(allowPaths))) {
      outside.push(absolute)
      allRegenerable = false
      continue
    }
    if (!isRegenerable(absolute, roots, regenerable)) allRegenerable = false
  }

  if (outside.length > 0) {
    const policy = opts.outsidePolicy === 'ask' ? 'ask' : 'deny'
    return make(
      policy,
      removal ? 'outside-workspace-delete' : 'outside-workspace-write',
      removal,
      `it touches ${outside.map((p) => `"${p}"`).join(', ')}, outside the session workspace`,
      'work inside the workspace, or ask the user to add the path to hard-gate.extraRoots.',
      targets,
      removal || overwrite,
    )
  }

  if (removal && FIND_DELETE.test(cmd)) {
    return make(
      'ask',
      'find-delete',
      true,
      'it deletes every file a `find` predicate matches, so the targets are not visible to the gate',
      'run the same `find` without `-delete` first, then delete the listed paths explicitly.',
      targets,
    )
  }

  if (removal && RSYNC_DELETE.test(cmd)) {
    return make(
      'ask',
      'rsync-delete',
      true,
      '`rsync --delete` removes destination files that are absent from the source',
      'run it once with `--dry-run` to review exactly what would be removed.',
      targets,
    )
  }

  if (removal && unresolved.length > 0) {
    return make(
      'ask',
      'unverifiable-target',
      true,
      `the delete target ${unresolved.map((p) => `"${p}"`).join(', ')} cannot be resolved before running`,
      'pass literal paths to the delete command so they can be checked first.',
      targets,
    )
  }

  if (removal && operands.length === 0) {
    return make(
      'ask',
      'pipeline-delete',
      true,
      'it deletes whatever arrives on the pipeline, so the targets are invisible to the gate',
      'list the exact paths first, then delete them explicitly.',
      targets,
    )
  }

  if (removal && /\*/.test(cmd) && !allRegenerable) {
    return make('ask', 'wildcard-delete', true, 'it deletes with a wildcard', undefined, targets)
  }

  if (removal && RECURSIVE.test(cmd) && !allRegenerable) {
    return make('ask', 'recursive-delete', true, 'it deletes recursively', undefined, targets)
  }

  return make('allow', removal ? 'local-delete' : 'local-write', removal, undefined, undefined, targets, removal || overwrite)
}

/**
 * Extract the path operands of a command.
 *
 * Quoted tokens are always operands. Bare tokens are operands unless they are a
 * switch (`-Recurse`), a known verb, or a literal boolean. A variable we cannot
 * expand becomes an unresolved operand rather than being silently dropped.
 *
 * @param {string} command
 * @param {string} [cwd]
 * @returns {{ text: string, absolute?: string, unresolved?: true }[]}
 */
export function operandsOf(command, cwd) {
  const base = typeof cwd === 'string' && cwd.length > 0 ? cwd : process.cwd()
  const operands = []
  const pattern = /"([^"]*)"|'([^']*)'|([^\s"'`;|&<>()]+)/g
  let match
  while ((match = pattern.exec(command)) !== null) {
    const raw = match[1] ?? match[2] ?? match[3] ?? ''
    const token = raw.trim()
    if (token === '') continue
    if (token.startsWith('-')) continue
    // A Windows-style switch (`/s`, `/q`, `/MIR`) is never a path; a real POSIX
    // path at the root has at least one more segment.
    if (/^\/[A-Za-z]{1,3}$/.test(token)) continue
    // A quoted phrase with whitespace is prose (`"Remove-Item -Recurse"`), not a
    // single path operand. Unquoted tokens cannot contain whitespace by design.
    if (match[1] !== undefined || match[2] !== undefined) {
      if (/\s/.test(token)) continue
    }
    if (NON_OPERANDS.has(token.toLowerCase())) continue
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) continue

    const expanded = expandVariables(token)
    if (expanded === undefined) {
      operands.push({ text: token, unresolved: true })
      continue
    }
    operands.push({ text: token, absolute: resolveFrom(expanded, base) })
  }
  return operands
}

/**
 * Expand `$env:NAME`, `$HOME`, `$PWD`, and `%NAME%`. Returns `undefined` for a
 * variable that cannot be resolved statically.
 */
function expandVariables(token) {
  let value = token
  if (/^\$env:/i.test(value)) {
    const match = /^\$env:([A-Za-z_][A-Za-z0-9_]*)([\s\S]*)$/i.exec(value)
    if (match === null) return undefined
    const resolved = process.env[match[1]] ?? process.env[match[1].toUpperCase()]
    if (resolved === undefined) return undefined
    return resolved + match[2]
  }
  if (/^%[A-Za-z_][A-Za-z0-9_]*%/.test(value)) {
    const match = /^%([A-Za-z_][A-Za-z0-9_]*)%([\s\S]*)$/.exec(value)
    if (match === null) return undefined
    const resolved = process.env[match[1]]
    if (resolved === undefined) return undefined
    return resolved + match[2]
  }
  if (value === '$HOME' || value.startsWith('$HOME/') || value.startsWith('$HOME\\')) {
    return homedir() + value.slice(5)
  }
  if (value === '$PWD') return process.cwd()
  if (value.startsWith('$')) return undefined
  return expandHome(value)
}

/** Whether a token names a filesystem path rather than a bare word. */
function looksLikePath(token) {
  if (token === '.' || token === '..') return true
  if (/^[A-Za-z]:/.test(token)) return true
  if (token.startsWith('\\\\')) return true
  if (token.startsWith('~')) return true
  if (token.startsWith('/') && token.length > 1) return true
  if (token.includes('\\') || token.includes('/')) return true
  return false
}

/** Resolve an already-expanded operand against the command's working directory. */
function resolveFrom(value, cwd) {
  const expanded = unquote(value)
  return isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded)
}

function insideAny(absolute, roots) {
  for (const root of roots) {
    if (typeof root === 'string' && root.length > 0 && isUnder(absolute, root)) return true
  }
  return false
}

/** Whether the target itself is a regenerable directory inside a workspace root. */
function isRegenerable(absolute, roots, regenerable) {
  if (regenerable.size === 0) return false
  for (const root of roots) {
    const segments = relativeSegments(absolute, root)
    if (segments === undefined || segments.length === 0) continue
    return regenerable.has(segments.at(-1).toLowerCase())
  }
  return false
}

/** Whether the command redirects output into a file. */
function hasRedirect(command) {
  return /(?:^|[^0-9&])>{1,2}\s*(?![&$]|$)/.test(command)
}

function make(level, rule, destructive, why, hint, targets, overwrites) {
  const parts = []
  if (why !== undefined) parts.push(`hard-gate: ${why}.`)
  if (hint !== undefined) parts.push(hint)
  return {
    level,
    rule,
    destructive: Boolean(destructive),
    overwrites: Boolean(overwrites ?? destructive),
    targets: Array.isArray(targets) ? targets : [],
    reason: parts.length > 0 ? parts.join(' ') : undefined,
  }
}

/** Exported for tests. */
export const internals = { CATASTROPHIC, DELETE_VERB, RECURSIVE, expandVariables, looksLikePath, hasRedirect }
