/**
 * Path identity helpers for the hard gate.
 *
 * Every path decision is made on a *key*: a normalized spelling that is
 * case-folded on Windows and free of the Win32 extended-length prefix. Keys are
 * compared lexically; {@link canonicalTarget} additionally resolves the deepest
 * existing ancestor so junctions and 8.3 aliases cannot smuggle a write past a
 * containment check.
 *
 * @module dsh-hard-gate/paths
 */

import { realpath } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path'
import { homedir } from 'node:os'

/** Whether this process runs on Windows (path identity is case-insensitive there). */
export const IS_WINDOWS = process.platform === 'win32'

const EXTENDED_PREFIX = /^\\\\\?\\/
const EXTENDED_UNC = /^\\\\\?\\UNC\\/i

/** Remove the `\\?\` / `\\?\UNC\` prefix Win32 canonical paths carry. */
export function stripExtended(input) {
  const value = String(input)
  if (EXTENDED_UNC.test(value)) return `\\\\${value.slice(8)}`
  return value.replace(EXTENDED_PREFIX, '')
}

/** Strip one layer of matching quotes. */
export function unquote(input) {
  const value = String(input).trim()
  if (value.length >= 2) {
    const first = value[0]
    const last = value[value.length - 1]
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) return value.slice(1, -1)
  }
  return value
}

/** Expand a leading `~` to the current user's home directory. */
export function expandHome(input) {
  const value = String(input)
  if (value === '~') return homedir()
  if (value.startsWith('~/') || value.startsWith('~\\')) return join(homedir(), value.slice(2))
  return value
}

/**
 * Normalize a path for comparison: unquoted, prefix-free, separator-unified,
 * and dot-segment collapsed. Does not resolve links and does not touch disk.
 */
export function normalizeForMatch(input) {
  let value = stripExtended(unquote(input))
  if (IS_WINDOWS) {
    // Preserve the leading `\\` of a UNC share while collapsing the rest.
    value = value.startsWith('\\\\')
      ? `\\\\${value.slice(2).replace(/[\\/]+/g, '\\')}`
      : value.replace(/[\\/]+/g, '\\')
  } else {
    value = value.replace(/\/+/g, '/')
  }
  return normalize(value)
}

/** Comparison key for a path: normalized, and case-folded on Windows. */
export function pathKey(input) {
  const value = normalizeForMatch(input)
  return IS_WINDOWS ? value.toLowerCase() : value
}

/** Resolve `input` against `cwd` without touching disk. */
export function lexicalTarget(cwd, input) {
  const expanded = expandHome(unquote(input))
  return normalizeForMatch(isAbsolute(expanded) ? expanded : resolve(cwd, expanded))
}

/**
 * Resolve `input` against `cwd` and canonicalize the deepest existing ancestor.
 * A target that does not exist yet still gets its existing parent resolved, so a
 * create cannot be aimed through a junction at a protected tree.
 *
 * @param {string} cwd - session working directory.
 * @param {string} input - model-supplied path.
 * @returns {Promise<string>} canonical absolute path.
 */
export async function canonicalTarget(cwd, input) {
  const lexical = lexicalTarget(cwd, input)
  let current = lexical
  const tail = []
  for (;;) {
    try {
      const resolved = await realpath(current)
      return normalizeForMatch(tail.length > 0 ? join(resolved, ...tail.reverse()) : resolved)
    } catch {
      const parent = dirname(current)
      if (parent === current) return lexical
      tail.push(basename(current))
      current = parent
    }
  }
}

/** Whether `child` is `root` or lives under it. Both operands are paths, not keys. */
export function isUnder(child, root) {
  const childKey = pathKey(child)
  const rootKey = pathKey(root)
  if (childKey === rootKey) return true
  const prefix = rootKey.endsWith(sep) ? rootKey : rootKey + sep
  return childKey.startsWith(prefix)
}

/**
 * Path segments of `child` relative to `root`, or `undefined` when outside.
 *
 * @returns {string[] | undefined}
 */
export function relativeSegments(child, root) {
  if (!isUnder(child, root)) return undefined
  const rel = relative(pathKey(root), pathKey(child))
  if (rel === '') return []
  return rel.split(sep).filter((segment) => segment.length > 0)
}

/**
 * Match a key against protected roots, protected path segments, and protected
 * file names. Returns the rule that matched, or `undefined`.
 *
 * @param {string} key - comparison key.
 * @param {{ roots: string[], segments: Set<string>, basenames: Set<string> }} rules
 * @returns {string | undefined}
 */
export function matchProtected(key, rules) {
  for (const root of rules.roots) {
    if (isUnder(key, root)) return root
  }
  const segments = key.split(sep).filter((segment) => segment.length > 0)
  for (const segment of segments) {
    if (rules.segments.has(segment.toLowerCase())) return segment
  }
  const base = segments.at(-1)
  if (base !== undefined) {
    if (rules.basenames.has(base.toLowerCase())) return base
    if (/(?:^|\.)credentials?(?:\.|$)/i.test(base)) return base
  }
  return undefined
}

/**
 * Protected roots that are unsafe for any agent to rewrite, independent of the
 * session workspace. Deliberately conservative on the user profile: credential
 * stores live there, and Harness itself keeps profiles under `~/.dsh`.
 *
 * @returns {string[]} absolute paths.
 */
export function defaultProtectedRoots() {
  const home = homedir()
  const roots = [
    join(home, '.ssh'),
    join(home, '.dsh'),
    join(home, '.aws'),
    join(home, '.azure'),
    join(home, '.gnupg'),
    join(home, '.kube'),
    join(home, '.config', 'gh'),
  ]
  if (IS_WINDOWS) {
    roots.push(join(home, 'AppData'))
    for (const name of ['WINDIR', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData']) {
      const value = process.env[name]
      if (typeof value === 'string' && value.length > 0) roots.push(value)
    }
    for (const drive of ['C', 'D', 'E', 'F', 'G']) {
      roots.push(`${drive}:\\System Volume Information`, `${drive}:\\$Recycle.Bin`)
    }
  } else {
    roots.push('/etc', '/usr', '/bin', '/sbin', '/boot', '/dev', '/proc', '/sys', '/var/lib')
  }
  return roots
}
