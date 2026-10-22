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

/** Verbs whose normal use writes or replaces an object in place. */
const WRITE_VERB = /\b(?:set-content|add-content|ac|out-file|new-item|ni|clear-content|clc|tee-object|tee|truncate|export-csv|export-clixml|sc)\b/i

/** Verbs that copy or move data; only the destination is a write target. */
const TRANSFER_VERB = /\b(?:copy|copy-item|cp|cpi|move|move-item|mv|mi|rename-item|ren|replace|robocopy|xcopy|scp|rsync)\b/i

/** Verbs that download to a local file; only the output flag is a write target. */
const DOWNLOAD_VERB = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|certutil)\b/i

/** Verbs that extract archives; only the destination flag is a write target. */
const EXTRACT_VERB = /\b(?:tar|7z|unzip|expand-archive)\b/i

/** In-place stream editors (sed -i, perl -pi) rewrite their file operands. */
const INPLACE_VERB = /\b(?:sed|perl)\b[^\n;|&]*(?:\s-[a-z]*i\b|\s--in-place\b)/i

/** dd writes only to its of= target. */
const DD_VERB = /\bdd\b/i
const DD_OF = /\bof=(?:"[^"]+"|'[^']+'|[^\s"']+)/i

/** Files that commonly hold credentials. */
const SECRET_FILE = /(?:^|[\s"'=@:/\\])(?:\.env(?!\.(?:example|sample|template|dist)\b)(?:\.[\w.-]+)?|id_rsa(?!\.pub)|id_ed25519(?!\.pub)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|[\w.-]+\.(?:pem|key|p12|pfx))\b/i
const STRICT_SECRET_FILE = /(?:^|[\s"'=@:/\\])(?:id_rsa(?!\.pub)|id_ed25519(?!\.pub)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|[\w.-]+\.(?:pem|key|p12|pfx))\b/i
const EXFIL_TOOL = /\b(?:curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm|scp|sftp|ftp|rsync)\b/i
const UPLOAD_HINT = /(?:-F\s+\S*=@|--form\s+\S*=@|-T\s+\S+|(?:-d|--data(?:-binary|-raw)?)\s+@|--upload-file|-InFile\b|--post-file)/i
const READ_VERB = /\b(?:get-content|gc|cat|type|more|less|head|tail|strings|xxd|od)\b/i

/** Commands that accept PowerShell's -WhatIf common parameter. */
const WHATIF_VERB = /^\s*(?:remove-item|ri|rm|del|erase|rmdir|rd|move-item|mv|copy-item|cp|rename-item|ren|set-content|add-content|out-file|new-item|ni|clear-content|clc)\b/i

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
const GIT_CLEAN = new RegExp(String.raw`${GIT_PREFIX}clean\b([^\n;|&]*)`, 'gi')

const GIT_INVOCATION = /(?:^|[;&|]\s*)\bgit(?:\.exe)?\s+(?:(?:(?:-C|-c|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix)\s+(?:"[^"]*"|'[^']*'|\S+)|--[a-z][a-z-]*(?:=\S+)?|-[A-Za-z])\s+)*([a-z][a-z-]*)\b([^\n;|&]*)/gi

/** A target at a filesystem root, a drive root, or the home directory. */
const CATASTROPHIC = /(?:^|[\s"'`=])(?:[a-z]:[\\/]?(?=[\s"'`;|&)]|$)|\\\\[^\\\s"'`]+\\(?:[^\\\s"'`]+)?(?=[\s"'`;|&)]|$)|~(?=[\s"'`;|&)]|$)|\$home(?=[\s"'`;|&)]|$)|\$env:(?:userprofile|home)(?=[\s"'`;|&)]|$)|(?:\/(?:\*)?)(?=[\s"'`;|&)]|$))/i

/** Tokens that are never path operands. */
const NON_OPERANDS = new Set([
  'remove-item', 'ri', 'rm', 'rmdir', 'rd', 'del', 'erase',
  'move-item', 'move', 'mv', 'mi', 'copy-item', 'copy', 'cp', 'cpi',
  'rename-item', 'ren',
  'set-content', 'add-content', 'ac', 'out-file', 'new-item', 'ni',
  'clear-content', 'clc', 'robocopy', 'xcopy', 'tee-object', 'tee',
  'replace', 'scp', 'rsync', 'curl', 'wget', 'iwr', 'irm',
  'invoke-webrequest', 'invoke-restmethod', 'start-bitstransfer', 'certutil',
  'tar', '7z', 'unzip', 'expand-archive', 'dd', 'sed', 'perl',
  'export-csv', 'export-clixml', 'sc',
  'get-childitem', 'gci', 'ls', 'dir', 'where-object', 'foreach-object',
  'select-object', 'sort-object', 'measure-object', 'format-table',
  'out-string', 'write-output', 'write-host', 'find', 'echo',
  '$null', '$true', '$false',
])

const MOVE_VERB = /\b(?:move|move-item|mv|mi|rename-item|ren)\b/i

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
    why: 'git clean -x permanently deletes untracked AND ignored files (build output, local config, .env)',
    hint: 'run git clean -ndx first to list exactly what would be deleted, then remove specific paths.',
  },
  {
    id: 'power-state',
    test: (c) => /(?:^|[;&|]\s*)\s*(?:shutdown|stop-computer|restart-computer|logoff)\b/i.test(c),
    why: 'it shuts down, restarts, or logs off the machine',
  },
  {
    id: 'raw-device',
    test: (c) => /(?:\\\\\.\\(?:[a-z]:|physicaldrive\d+)|\bdd\b[^\n;|&]*\bof=\/dev\/(?:sd|nvme|hd|disk)|\bmkfs(?:\.\w+)?\b|\bfdisk\b)/i.test(c),
    why: 'it writes to a raw device or reformats a filesystem',
  },
  {
    id: 'secret-exfil',
    test: (c) => isSecretExfil(c),
    why: 'it sends a private key or credential file to a network endpoint',
    hint: 'never upload secrets; use a scoped token and redact the value.',
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
    why: 'git clean deletes untracked files without any recovery path',
    hint: 'run git clean -nd first to list exactly what would be deleted.',
  },
  {
    id: 'git-destructive',
    test: (c) => isGitDestructive(c),
    why: 'it discards or rewrites Git history or uncommitted work',
  },
  {
    id: 'mirror-copy',
    test: (c) => !/\/L\b/i.test(c) && /\brobocopy\b[^\n;|&]*\/(?:mir|purge)\b/i.test(c),
    why: 'robocopy /MIR deletes every destination file that is absent from the source',
  },
  {
    id: 'inline-code',
    test: (c) => /(?:^|[;&|]\s*)(?:node|nodejs)\s+(?:-e|--eval)\b|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b|\b(?:powershell|pwsh)(?:\.exe)?\s+(?:-\w+\s+)*-(?:e|enc|encodedcommand|command|c)\b|\bcmd(?:\.exe)?\s+\/[ck]\b|\b(?:ba|z|fi)?sh\s+-c\b|\b(?:iex|invoke-expression)\b|\[scriptblock\]::create|\badd-type\b/i.test(c),
    why: 'inline interpreter code hides its real file operations from the gate',
    hint: 'write the program to a file in the workspace and run that file instead.',
  },
  {
    id: 'download-execute',
    test: (c) => /(?:invoke-webrequest|invoke-restmethod|iwr|irm|curl|wget)[^\n;|&]*\|[^\n]*\b(?:iex|invoke-expression|sh|bash)\b|(?:^|[;&|]\s*)iex\s*\(|\bcertutil(?:\.exe)?\b[^\n;|&]*-urlcache\b|\bbitsadmin(?:\.exe)?\b[^\n;|&]*\/transfer\b/i.test(c),
    why: 'it downloads and executes remote code',
  },
  {
    id: 'publish',
    test: (c) => !/--dry-run\b/i.test(c) && /\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bdotnet\s+nuget\s+push\b|\bcargo\s+publish\b/i.test(c),
    why: 'it publishes artifacts to a remote registry',
  },
  {
    id: 'elevate',
    test: (c) => /-verb\s+runas\b|\bsudo\b|\bgsudo\b/i.test(c),
    why: 'it requests elevation',
  },
  {
    id: 'secret-read',
    test: (c) => isSecretRead(c),
    why: 'it reads a private key or credential file',
    hint: 'read the secret only if the user explicitly asked, and never send it to a network tool.',
  },
  {
    id: 'hidden-exec',
    test: (c) => /(?:^|[;&|]\s*|\|\s*)(?:mshta|rundll32|regsvr32|wscript|cscript|start-job|wsl)\b|\bstart-process\b[^\n;|&]*(?:-windowstyle\s+hidden|-credential)\b/i.test(c),
    why: 'it launches a hidden or indirect interpreter that the gate cannot inspect',
    hint: 'run the program directly, or write the script to the workspace and run that file.',
  },
  {
    id: 'persistence',
    test: (c) => /\bschtasks(?:\.exe)?\b[^\n;|&]*\/create\b|\bregister-scheduledtask\b|\bnew-service\b|\bsc(?:\.exe)?\s+create\b|\breg(?:\.exe)?\s+(?:add|import)\b|\bsetx(?:\.exe)?\b|\bwmic(?:\.exe)?\s+process\s+call\s+create\b/i.test(c),
    why: 'it creates a scheduled task, service, registry entry, or other persistence mechanism',
    hint: 'persistence changes are the user\'s decision, not part of a coding task.',
  },
  {
    id: 'service-control',
    test: (c) => /\b(?:stop-service|restart-service|set-service|suspend-service|resume-service)\b|\bsc(?:\.exe)?\s+(?:stop|start|config|pause|continue)\b|\bnet\s+(?:stop|start)\b/i.test(c),
    why: 'it stops, starts, or reconfigures a system service',
  },
  {
    id: 'process-kill',
    test: (c) => /\btaskkill(?:\.exe)?\b[^\n;|&]*\/f\b|\bstop-process\b[^\n;|&]*-force\b/i.test(c),
    why: 'it force-terminates running processes',
  },
  {
    id: 'global-install',
    test: (c) => /\b(?:npm|pnpm)\s+(?:i|install|add)\b[^\n;|&]*(?:\s-g\b|\s--global\b)|\byarn\s+global\s+add\b|\bwinget\s+install\b|\bchoco\s+install\b|\bscoop\s+install\b|\bcargo\s+install\b|\bgo\s+install\b|\bpip[0-9.]*\s+install\b[^\n;|&]*--user\b/i.test(c),
    why: 'it installs software outside the workspace, where the gate cannot track it',
  },
]

/**
 * Extract the git clean flag cluster for every git clean invocation in the
 * command. A destructive invocation anywhere wins over a dry run elsewhere.
 *
 * @param {string} command
 * @returns {Set<string> | undefined}
 */
function gitCleanFlags(command) {
  const matches = [...command.matchAll(GIT_CLEAN)]
  if (matches.length === 0) return undefined
  const parsed = matches.map((match) => {
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
  })
  const destructive = parsed.find((flags) => flags.has('f') && flags.has('x') && !flags.has('n'))
  if (destructive !== undefined) return destructive
  const ask = parsed.find((flags) => flags.has('f') && !flags.has('x') && !flags.has('n'))
  if (ask !== undefined) return ask
  return parsed[0]
}

/** Whether a git invocation rewrites history or discards uncommitted work. */
function isGitDestructive(command) {
  for (const match of command.matchAll(GIT_INVOCATION)) {
    const subcommand = match[1].toLowerCase()
    const args = (match[2] ?? '').trim()
    if (gitSubcommandDestructive(subcommand, args)) return true
  }
  return false
}

function gitSubcommandDestructive(subcommand, args) {
  switch (subcommand) {
    case 'push':
      return /(?:^|\s)-[a-z]*f(?:\s|$)/i.test(args) || /(?:^|\s)--force(?:-with-lease|-if-includes)?(?:\s|$)/i.test(args) || /(?:^|\s)\+[^\s]+/.test(args) || /(?:^|\s)--(?:mirror|delete|prune)(?:\s|=|$)/i.test(args)
    case 'checkout':
      return /(?:^|\s)-[a-z]*f(?:\s|$)/i.test(args) || /(?:^|\s)--force(?:\s|$)/i.test(args) || /(?:^|\s)--(?:\s|$)/.test(args) || /(?:^|\s)(?:\.|\*)(?:\s|$)/.test(args)
    case 'restore':
      if (/(?:^|\s)--staged(?:\s|$)/i.test(args) && !/(?:^|\s)--worktree(?:\s|$)/i.test(args)) return false
      return true
    case 'switch':
      return /(?:^|\s)-[a-z]*f(?:\s|$)/i.test(args) || /(?:^|\s)--(?:force|discard-changes)(?:\s|$)/i.test(args)
    case 'branch':
      return /(?:^|\s)-[a-z]*[df](?:\s|$)/i.test(args) || /(?:^|\s)--(?:delete|force)(?:\s|$)/i.test(args)
    case 'tag':
      return /(?:^|\s)-[a-z]*[df](?:\s|$)/i.test(args) || /(?:^|\s)--delete(?:\s|$)/i.test(args)
    case 'update-ref':
      return /(?:^|\s)(?:-d|--delete)(?:\s|$)/i.test(args)
    case 'reflog':
      return /(?:^|\s)expire(?:\s|$)/i.test(args)
    case 'gc':
      return /(?:^|\s)--prune(?:=|\s+)now(?:\s|$)/i.test(args)
    case 'filter-branch':
    case 'filter-repo':
      return true
    case 'worktree':
      return /(?:^|\s)remove(?:\s|$)/i.test(args) && /(?:^|\s)(?:-f|--force)(?:\s|$)/i.test(args)
    case 'stash':
      return /(?:^|\s)(?:drop|clear)(?:\s|$)/i.test(args)
    case 'reset':
      return /(?:^|\s)--hard(?:\s|$)/i.test(args)
    case 'rm':
      return /(?:^|\s)-[a-z]*[rf](?:\s|$)/i.test(args)
    default:
      return false
  }
}

/** Whether the command sends a credential file to a network endpoint. */
function isSecretExfil(command) {
  if (!EXFIL_TOOL.test(command)) return false
  const local = command
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, ' ')
    .replace(/(?:^|\s)(?:-i|--identity|--key|--cert)\s+(?:"[^"]*"|'[^']*'|\S+)/gi, ' ')
  if (!SECRET_FILE.test(local)) return false
  if (/\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i.test(command)) {
    return UPLOAD_HINT.test(command)
  }
  if (/\b(?:scp|rsync|sftp|ftp)\b/i.test(command)) {
    const remote = command.replace(/\b[a-z]:[\\/]/gi, '')
    if (!/(?:@|:)/.test(remote)) return false
  }
  return true
}

/** Whether the command reads a private key or credential file. */
function isSecretRead(command) {
  return READ_VERB.test(command) && STRICT_SECRET_FILE.test(command)
}

/** A command with no separators can be a dry run as a whole. */
function isSingleSegment(command) {
  return !/[\n;&]|\|\|/.test(command)
}

/** Whether the whole command is a non-mutating preview. */
function isDryRun(command) {
  if (!isSingleSegment(command)) return false
  if (WHATIF_VERB.test(command) && /-whatif\b/i.test(command)) return true
  if (/\brobocopy\b[^\n;|&]*\/L\b/i.test(command)) return true
  if (/\b(?:npm|pnpm|yarn|cargo|dotnet|twine|git|rsync|az|aws|terraform)\b[^\n;|&]*--dry-run\b/i.test(command)) return true
  return false
}

/** The operands a command can write, rather than every operand it mentions. */
function targetOperands(command, operands, cwd) {
  if (DD_VERB.test(command)) return ddDestinations(command, cwd)
  if (DOWNLOAD_VERB.test(command)) return downloadDestinations(command, operands, cwd)
  if (EXTRACT_VERB.test(command)) return archiveDestinations(command, cwd)
  if (MOVE_VERB.test(command)) return operands
  if (TRANSFER_VERB.test(command)) {
    const last = operands.at(-1)
    return last === undefined ? [] : [last]
  }
  if (INPLACE_VERB.test(command)) return operands
  return operands
}

function downloadDestinations(command, operands, cwd) {
  const value = flagValue(command, ['-o', '--output', '--output-document', '-O', '-OutFile', '-Destination', '--output-dir', '-P', '--directory-prefix'])
  if (value !== undefined) {
    const operand = operandFromValue(value, cwd)
    return operand === undefined ? [] : [operand]
  }
  if (/\bcertutil(?:\.exe)?\b/i.test(command)) {
    const last = operands.at(-1)
    return last === undefined ? [] : [last]
  }
  return []
}

function archiveDestinations(command, cwd) {
  const value = flagValue(command, ['-C', '--directory', '-o', '-d', '-DestinationPath'])
  if (value === undefined) return []
  const operand = operandFromValue(value, cwd)
  return operand === undefined ? [] : [operand]
}

function ddDestinations(command, cwd) {
  const match = /(?:^|\s)of=("[^"]*"|'[^']*'|[^\s"']+)/i.exec(command)
  if (match === null) return []
  const operand = operandFromValue(match[1], cwd)
  return operand === undefined ? [] : [operand]
}

/** Read the value of the first matching long or short output flag. */
function flagValue(command, flags) {
  for (const flag of flags) {
    const escaped = flag
    const exact = new RegExp("(?:^|\\s)" + escaped + "(?:\\s+|[:=])(\"[^\"]*\"|'[^']*'|[^\\s\"']+)")
    const match = exact.exec(command)
    if (match !== null) return unquote(match[1])
    if (/^-[A-Za-z]$/.test(flag)) {
      const attached = new RegExp("(?:^|\\s)" + escaped + "([^\\s\"']+)")
      const attachedMatch = attached.exec(command)
      if (attachedMatch !== null) {
        const value = unquote(attachedMatch[1]).replace(/^[:=]/, '')
        if (plausiblePathValue(value)) return value
      }
    }
  }
  for (const flag of flags) {
    if (flag.length <= 2) continue
    const escaped = flag
    const loose = new RegExp("(?:^|\\s)" + escaped + "(?:\\s+|[:=])(\"[^\"]*\"|'[^']*'|[^\\s\"']+)", 'i')
    const match = loose.exec(command)
    if (match !== null) return unquote(match[1])
  }
  return undefined
}

/** A short attached flag value must look like a path, not a longer option. */
function plausiblePathValue(value) {
  if (value === '' || value === '-' || value === '/dev/null' || value === 'NUL' || value === 'nul') return false
  if (/^[A-Za-z]:/.test(value)) return true
  if (value.startsWith('/') || value.startsWith('\\') || value.startsWith('~')) return true
  if (value.includes('/') || value.includes('\\')) return true
  if (value.includes('.')) return true
  return false
}

function operandFromValue(value, cwd) {
  const clean = unquote(value).replace(/^[:=]/, '').trim()
  if (clean === '' || clean === '-' || clean === '/dev/null' || clean === 'NUL' || clean === 'nul') return undefined
  return { text: clean, absolute: resolveFrom(clean, cwd) }
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

  if (isDryRun(cmd)) return make('allow', 'dry-run', false)

  for (const rule of DENY_RULES) {
    if (rule.test(cmd)) return make('deny', rule.id, true, rule.why, rule.hint)
  }

  const operands = operandsOf(cmd, opts.cwd)
  const removal = DELETE_VERB.test(cmd) || FIND_DELETE.test(cmd) || RSYNC_DELETE.test(cmd)
  const overwrite = WRITE_VERB.test(cmd) || TRANSFER_VERB.test(cmd) || DOWNLOAD_VERB.test(cmd) || EXTRACT_VERB.test(cmd) || INPLACE_VERB.test(cmd) || DD_VERB.test(cmd) || hasRedirect(cmd)
  const checked = targetOperands(cmd, operands, opts.cwd)
  const targets = checked.filter((operand) => typeof operand.absolute === 'string').map((operand) => operand.absolute)

  for (const rule of ASK_RULES) {
    if (rule.test(cmd)) {
      const askTargets = rule.id === 'secret-read' ? [] : targets
      return make('ask', rule.id, true, rule.why, rule.hint, askTargets, true)
    }
  }

  if (!removal && !overwrite) return make('allow', 'default', false)

  const roots = Array.isArray(opts.workspaceRoots) ? opts.workspaceRoots : [opts.cwd]
  const allowPaths = Array.isArray(opts.allowPaths) ? opts.allowPaths : []
  const regenerable = opts.regenerable instanceof Set ? opts.regenerable : new Set()

  if (checked.some((operand) => CATASTROPHIC.test(operand.text) || /^[a-z]:[\\/]\*$/i.test(operand.text))) {
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
  let allRegenerable = checked.length > 0

  for (const operand of checked) {
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
      'it touches ' + outside.map((p) => '"' + p + '"').join(', ') + ', outside the session workspace',
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
      'it deletes every file a find predicate matches, so the targets are not visible to the gate',
      'run the same find without -delete first, then delete the listed paths explicitly.',
      targets,
    )
  }

  if (removal && RSYNC_DELETE.test(cmd)) {
    return make(
      'ask',
      'rsync-delete',
      true,
      'rsync --delete removes destination files that are absent from the source',
      'run it once with --dry-run to review exactly what would be removed.',
      targets,
    )
  }

  if (removal && unresolved.length > 0) {
    return make(
      'ask',
      'unverifiable-target',
      true,
      'the delete target ' + unresolved.map((p) => '"' + p + '"').join(', ') + ' cannot be resolved before running',
      'pass literal paths to the delete command so they can be checked first.',
      targets,
    )
  }

  if (removal && checked.length === 0) {
    return make(
      'ask',
      'pipeline-delete',
      true,
      'it deletes whatever arrives on the pipeline, so the targets are invisible to the gate',
      'list the exact paths first, then delete them explicitly.',
      targets,
    )
  }

  if (removal && checked.some((operand) => /\*/.test(operand.text)) && !allRegenerable) {
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
 * switch (-Recurse), a known verb, or a literal boolean. A variable we cannot
 * expand becomes an unresolved operand rather than being silently dropped.
 *
 * @param {string} command
 * @param {string} [cwd]
 * @returns {{ text: string, absolute?: string, unresolved?: true }[]}
 */
export function operandsOf(command, cwd) {
  const base = typeof cwd === 'string' && cwd.length > 0 ? cwd : process.cwd()
  const operands = []
  const pattern = /"([^"]*)"|'([^']*)'|([^\s"'\x60;|&<>()]+)/g
  let match
  while ((match = pattern.exec(command)) !== null) {
    const raw = match[1] ?? match[2] ?? match[3] ?? ''
    const token = raw.trim()
    if (token === '') continue
    if (token.startsWith('-')) continue
    if (/^\/[A-Za-z]{1,3}$/.test(token)) continue
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
    return segments.some((segment) => regenerable.has(segment.toLowerCase()))
  }
  return false
}

/** Whether the command redirects output into a file. */
function hasRedirect(command) {
  return /(?:^|[^0-9&])>{1,2}\s*(?![&$]|$)/.test(command)
}

function make(level, rule, destructive, why, hint, targets, overwrites) {
  const parts = []
  if (why !== undefined) parts.push('hard-gate: ' + why + '.')
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
export const internals = { CATASTROPHIC, DELETE_VERB, RECURSIVE, expandVariables, looksLikePath, hasRedirect, isGitDestructive, isSecretExfil, isSecretRead, targetOperands, isDryRun }
