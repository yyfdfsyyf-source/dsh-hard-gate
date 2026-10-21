/**
 * Restore points: zip the targets of a destructive call before the tool runs.
 *
 * Design rules:
 *  - The archive is written before the mutation, so a crash during the write
 *    still leaves a recoverable copy.
 *  - The store lives outside the workspace (`~/.dsh/hard-gate/backups`), which
 *    also means the gate's own containment rules protect it.
 *  - Size and file-count caps turn an oversized backup into an explicit user
 *    decision instead of silently skipping the safety net.
 *  - A Windows copy is sent to the Recycle Bin asynchronously; the authoritative
 *    copy stays in the store for `restore.js`.
 *
 * @module dsh-hard-gate/backup
 */

import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { appendFile, copyFile, lstat, mkdir, readFile, readdir, rename, stat, unlink, utimes, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, parse, relative, sep } from 'node:path'
import { promisify } from 'node:util'
import { expandHome, isUnder, pathKey } from './paths.js'
import { createZip, readZip } from './zip.js'

const execFileAsync = promisify(execFile)
const INDEX_FILE = 'index.jsonl'
const MANIFEST_ENTRY = '_hard-gate/manifest.json'
const PRUNE_INTERVAL_MS = 6 * 60 * 60 * 1000

const RECYCLE_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -AssemblyName Microsoft.VisualBasic',
  '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($env:HARD_GATE_BIN_FILE, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)',
].join('\n')

/** A backup that cannot be taken safely within the configured limits. */
export class BackupLimitError extends Error {
  constructor(message, detail) {
    super(message)
    this.name = 'BackupLimitError'
    this.detail = detail
  }
}

/** Default store location. */
export function defaultBackupDir() {
  return join(homedir(), '.dsh', 'hard-gate', 'backups')
}

/**
 * Create the backup store used by the gate.
 *
 * @param {{ logger?: { info?(message: string): void, warn?(message: string): void } }} ctx
 * @param {object} options
 */
export function createBackupStore(ctx, options) {
  const logger = ctx?.logger
  const dir = expandHome(options.dir ?? defaultBackupDir())
  const enabled = options.enabled !== false
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : 64 * 1024 * 1024
  const maxFiles = Number.isFinite(options.maxFiles) ? options.maxFiles : 2000
  const retentionDays = Number.isFinite(options.retentionDays) ? options.retentionDays : 14
  const maxTotalBytes = Number.isFinite(options.maxTotalBytes) ? options.maxTotalBytes : 512 * 1024 * 1024
  const recycleBin = options.recycleBin === 'always' || options.recycleBin === 'never' ? options.recycleBin : 'auto'
  const recycleBinMaxBytes = Number.isFinite(options.recycleBinMaxBytes) ? options.recycleBinMaxBytes : 16 * 1024 * 1024
  const skipDirs = new Set((options.skipDirs ?? ['.git', '.hg', '.svn']).map((name) => String(name).toLowerCase()))

  const indexPath = join(dir, INDEX_FILE)
  const pending = new Set()
  let indexChain = Promise.resolve()
  let lastPrune = 0
  let recycleWarningShown = false

  /**
   * Zip the given targets and record the restore point.
   *
   * @param {string[]} targets absolute paths.
   * @param {{ tool?: string, rule?: string, cwd?: string, roots?: string[], session?: object, bin?: boolean }} meta
   * @returns {Promise<{ ok: true, empty?: true, id?: string, zip?: string, bytes?: number, sourceBytes?: number, files?: number, bin?: boolean }>}
   */
  async function backup(targets, meta) {
    if (!enabled) return { ok: true, empty: true }

    const unique = []
    const seen = new Set()
    for (const target of Array.isArray(targets) ? targets : []) {
      if (typeof target !== 'string' || target.length === 0 || !isAbsolute(target)) continue
      if (isUnder(target, dir)) continue
      const key = pathKey(target)
      if (seen.has(key)) continue
      seen.add(key)
      unique.push(target)
    }
    if (unique.length === 0) return { ok: true, empty: true }

    const cwd = typeof meta?.cwd === 'string' && meta.cwd.length > 0 ? meta.cwd : process.cwd()
    const gathered = await gather(unique, cwd, dir, skipDirs, maxBytes, maxFiles)
    if (gathered.items.length === 0) return { ok: true, empty: true }

    const now = new Date()
    const id = `${stampOf(now)}-${randomBytes(3).toString('hex')}`
    const sessions = sessionId(meta?.session)
    const roots = Array.isArray(meta?.roots) ? meta.roots.filter((root) => typeof root === 'string' && isAbsolute(root)) : [cwd]
    const manifest = {
      version: 1,
      id,
      at: now.toISOString(),
      tool: typeof meta?.tool === 'string' ? meta.tool : undefined,
      rule: typeof meta?.rule === 'string' ? meta.rule : undefined,
      cwd,
      roots,
      session: sessions,
      complete: gathered.errors.length === 0,
      items: gathered.items,
      skipped: gathered.skipped,
    }

    let manifestEntry = MANIFEST_ENTRY
    while (gathered.entries.some((entry) => entry.name === manifestEntry)) manifestEntry = `_${manifestEntry}`
    manifest.manifestEntry = manifestEntry

    const entries = gathered.entries.concat([{
      name: manifestEntry,
      data: Buffer.from(JSON.stringify(manifest, undefined, 2), 'utf8'),
      mtime: now,
    }])
    const archive = await createZip(entries)

    const day = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`
    const dayDir = join(dir, day)
    const zipPath = join(dayDir, `${id}.zip`)
    await mkdir(dayDir, { recursive: true })
    const temporary = `${zipPath}.tmp-${randomBytes(4).toString('hex')}`
    await writeFile(temporary, archive, { mode: 0o600 })
    await rename(temporary, zipPath)

    const wantsBin = meta?.bin !== false && binSupported()
    const bin = wantsBin && recycleBinMaxBytes > 0 && archive.length <= recycleBinMaxBytes
    if (bin) sendToRecycleBin(zipPath, id, archive.length)

    const record = {
      id,
      at: manifest.at,
      tool: manifest.tool,
      rule: manifest.rule,
      cwd,
      session: sessions,
      zip: zipPath,
      manifestEntry,
      zipBytes: archive.length,
      sourceBytes: gathered.bytes,
      files: gathered.items.length,
      skipped: gathered.skipped.length,
      complete: manifest.complete,
      bin,
    }
    try {
      await appendIndex(record)
    } catch (error) {
      logger?.warn?.(`hard-gate: restore point ${id} was written but its index entry failed: ${error?.message ?? error}`)
    }
    if (gathered.errors.length > 0) {
      logger?.warn?.(`hard-gate: restore point ${id} is partial (${gathered.errors.length} unreadable path(s)); see its manifest`)
    }
    schedulePrune(zipPath)

    return {
      ok: true,
      id,
      zip: zipPath,
      bytes: archive.length,
      sourceBytes: gathered.bytes,
      files: gathered.items.length,
      bin,
    }
  }

  function appendIndex(record) {
    const line = `${JSON.stringify(record)}\n`
    indexChain = indexChain.catch(() => {}).then(() => appendFile(indexPath, line, { encoding: 'utf8', mode: 0o600 }))
    return indexChain
  }

  function binSupported() {
    if (recycleBin === 'never') return false
    if (process.platform === 'win32') return true
    if (recycleBin === 'always' && !recycleWarningShown) {
      recycleWarningShown = true
      logger?.warn?.('hard-gate: recycleBin "always" is only implemented on Windows; keeping the store copy only')
    }
    return false
  }

  /**
   * Send a copy of the archive to the Windows Recycle Bin. The copy is
   * fire-and-forget: the authoritative archive is already in the store, so a
   * slow or blocked PowerShell must not delay the tool call.
   */
  function sendToRecycleBin(zipPath, id, size) {
    const copy = join(tmpdir(), `hard-gate-${id}.zip`)
    const task = (async () => {
      await copyFile(zipPath, copy)
      await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', RECYCLE_SCRIPT], {
        env: { ...process.env, HARD_GATE_BIN_FILE: copy },
        windowsHide: true,
        timeout: 20000,
        maxBuffer: 64 * 1024,
      })
    })().catch(async (error) => {
      logger?.warn?.(`hard-gate: could not copy restore point ${id} to the Recycle Bin: ${error?.message ?? error}`)
      await unlink(copy).catch(() => {})
    })
    pending.add(task)
    void task.finally(() => pending.delete(task))
    return size
  }

  function schedulePrune(keep) {
    void prune({ keep }).catch((error) => {
      logger?.warn?.(`hard-gate: restore-point pruning failed: ${error?.message ?? error}`)
    })
  }

  /**
   * Enforce the retention window and total-size budget.
   *
   * @param {{ force?: boolean, keep?: string }} [options]
   */
  async function prune(options = {}) {
    if (retentionDays <= 0 && maxTotalBytes <= 0) return { removed: 0, bytes: 0 }
    const now = Date.now()
    if (!options.force && now - lastPrune < PRUNE_INTERVAL_MS) return { removed: 0, bytes: 0 }
    lastPrune = now

    let days
    try {
      days = await readdir(dir, { withFileTypes: true })
    } catch {
      return { removed: 0, bytes: 0 }
    }

    /** @type {{ path: string, mtimeMs: number, size: number }[]} */
    const archives = []
    for (const entry of days) {
      if (!entry.isDirectory() || !/^\d{8}$/.test(entry.name)) continue
      const dayDir = join(dir, entry.name)
      for (const file of await readdir(dayDir, { withFileTypes: true }).catch(() => [])) {
        if (!file.isFile() || !file.name.endsWith('.zip')) continue
        const path = join(dayDir, file.name)
        if (options.keep !== undefined && pathKey(path) === pathKey(options.keep)) continue
        const info = await stat(path).catch(() => undefined)
        if (info !== undefined) archives.push({ path, mtimeMs: info.mtimeMs, size: info.size })
      }
    }

    let removed = 0
    let bytes = 0
    const cutoff = retentionDays > 0 ? now - retentionDays * 24 * 60 * 60 * 1000 : 0
    const survivors = []
    for (const archive of archives) {
      if (cutoff > 0 && archive.mtimeMs < cutoff) {
        if (await unlink(archive.path).then(() => true, () => false)) {
          removed += 1
          bytes += archive.size
        }
      } else {
        survivors.push(archive)
      }
    }

    let total = survivors.reduce((sum, archive) => sum + archive.size, 0)
    if (maxTotalBytes > 0 && total > maxTotalBytes) {
      survivors.sort((left, right) => left.mtimeMs - right.mtimeMs)
      for (const archive of survivors) {
        if (total <= maxTotalBytes) break
        if (await unlink(archive.path).then(() => true, () => false)) {
          removed += 1
          bytes += archive.size
          total -= archive.size
        }
      }
    }

    return { removed, bytes }
  }

  async function dispose() {
    // Pending Recycle Bin copies are deliberately not awaited: each one already
    // has a durable archive in the store, and teardown must not block on a
    // PowerShell process.
    pending.clear()
  }

  return { backup, prune, dispose, dir }
}

/** Snapshot one or more targets. */
async function gather(targets, cwd, storeDir, skipDirs, maxBytes, maxFiles) {
  const entries = []
  const items = []
  const skipped = []
  const errors = []
  const usedNames = new Set()
  let bytes = 0

  const addFile = async (absolute, explicit) => {
    let info
    try {
      info = await lstat(absolute)
    } catch (error) {
      if (explicit && error?.code !== 'ENOENT') throw error
      if (error?.code !== 'ENOENT') errors.push(absolute)
      return
    }
    if (info.isSymbolicLink()) {
      skipped.push(absolute)
      return
    }
    if (!info.isFile()) {
      skipped.push(absolute)
      return
    }
    if (maxBytes > 0 && bytes + info.size > maxBytes) {
      throw new BackupLimitError(`restore point would exceed ${formatBytes(maxBytes)}`, { path: absolute, bytes })
    }
    if (maxFiles > 0 && items.length >= maxFiles) {
      throw new BackupLimitError(`restore point would exceed ${maxFiles} files`, { path: absolute })
    }
    let data
    try {
      data = await readFile(absolute)
    } catch (error) {
      if (explicit) throw error
      errors.push(absolute)
      return
    }
    bytes += data.length
    const name = uniqueness(entryName(absolute, cwd), usedNames)
    entries.push({ name, data, mtime: info.mtime })
    items.push({
      path: absolute,
      kind: 'file',
      size: data.length,
      entry: name,
      mode: info.mode & 0o777,
      mtimeMs: info.mtimeMs,
    })
  }

  const addPath = async (absolute, explicit) => {
    let info
    try {
      info = await lstat(absolute)
    } catch (error) {
      if (explicit && error?.code !== 'ENOENT') throw error
      if (error?.code !== 'ENOENT') errors.push(absolute)
      return
    }
    if (info.isSymbolicLink()) {
      skipped.push(absolute)
      return
    }
    if (info.isFile()) {
      await addFile(absolute, explicit)
      return
    }
    if (!info.isDirectory()) {
      skipped.push(absolute)
      return
    }
    if (isUnder(absolute, storeDir) || skipDirs.has(basename(absolute).toLowerCase())) {
      skipped.push(absolute)
      return
    }

    let children
    try {
      children = await readdir(absolute, { withFileTypes: true })
    } catch (error) {
      if (explicit) throw error
      errors.push(absolute)
      return
    }
    if (children.length === 0) {
      if (maxFiles > 0 && items.length >= maxFiles) {
        throw new BackupLimitError(`restore point would exceed ${maxFiles} files`, { path: absolute })
      }
      // Empty directories carry no bytes but are part of the tree the user is
      // about to delete; record them so a restore recreates the shape.
      items.push({ path: absolute, kind: 'dir', mode: info.mode & 0o777, mtimeMs: info.mtimeMs })
    }
    for (const child of children) {
      const childPath = join(absolute, child.name)
      if (child.isSymbolicLink()) {
        skipped.push(childPath)
        continue
      }
      if (child.isDirectory()) {
        if (skipDirs.has(child.name.toLowerCase()) || isUnder(childPath, storeDir)) {
          skipped.push(childPath)
          continue
        }
        await addPath(childPath, false)
      } else if (child.isFile()) {
        await addFile(childPath, false)
      } else {
        skipped.push(childPath)
      }
    }
  }

  for (const target of targets) await addPath(target, true)
  return { entries, items, skipped, errors, bytes }
}

/** Path inside the archive: relative to the workspace when possible. */
function entryName(absolute, cwd) {
  if (isUnder(absolute, cwd)) {
    const value = toPosix(relative(cwd, absolute))
    return value.length > 0 ? value : basename(absolute)
  }
  const parsed = parse(absolute)
  const value = toPosix(relative(parsed.root, absolute))
  return `${sanitizeRoot(parsed.root)}/${value.length > 0 ? value : basename(absolute)}`
}

function uniqueness(name, used) {
  let candidate = name
  let counter = 2
  while (used.has(candidate)) {
    const dot = name.lastIndexOf('.')
    candidate = dot > 0 ? `${name.slice(0, dot)}-${counter}${name.slice(dot)}` : `${name}-${counter}`
    counter += 1
  }
  used.add(candidate)
  return candidate
}

function sanitizeRoot(root) {
  const value = String(root).replace(/[:\\/]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase()
  return value.length > 0 ? value : 'root'
}

function toPosix(value) {
  return value.split(sep).join('/')
}

function pad(value) {
  return String(value).padStart(2, '0')
}

function stampOf(date) {
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`
}

function sessionId(session) {
  const value = typeof session === 'string' ? session : session?.id
  return typeof value === 'string' && value.length > 0 ? value.slice(0, 24) : undefined
}

function formatBytes(value) {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${value} B`
}

/**
 * Read the append-only index. Invalid lines are ignored so one interrupted
 * write cannot hide the rest of the history.
 *
 * @param {string} dir
 * @returns {Promise<object[]>}
 */
export async function readIndex(dir) {
  let text
  try {
    text = await readFile(join(expandHome(dir), INDEX_FILE), 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw error
  }
  const records = []
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '') continue
    try {
      const record = JSON.parse(line)
      if (record !== null && typeof record === 'object' && typeof record.id === 'string') records.push(record)
    } catch {
      // A torn line is expected after a hard shutdown; skip it.
    }
  }
  return records
}

/**
 * Restore one recorded archive.
 *
 * @param {object} record - an index record.
 * @param {{ force?: boolean, dryRun?: boolean }} [options]
 * @returns {Promise<{ id: string, restored: string[], conflicts: string[], skipped: { path: string, reason: string }[], dryRun: boolean }>}
 */
export async function restoreRecord(record, options = {}) {
  const force = options.force === true
  const dryRun = options.dryRun === true
  const entries = await readZip(await readFile(record.zip))
  const byName = new Map(entries.map((entry) => [entry.name, entry.data]))
  const manifestName = typeof record.manifestEntry === 'string' ? record.manifestEntry : MANIFEST_ENTRY
  const manifestRaw = byName.get(manifestName) ?? byName.get(MANIFEST_ENTRY) ?? byName.get(`_${MANIFEST_ENTRY}`)
  if (manifestRaw === undefined) throw new Error(`restore point ${record.id} has no manifest`)
  const manifest = JSON.parse(manifestRaw.toString('utf8'))
  if (manifest?.version !== 1 || !Array.isArray(manifest.items)) throw new Error(`restore point ${record.id} has an unsupported manifest`)

  const roots = Array.isArray(manifest.roots)
    ? manifest.roots.filter((root) => typeof root === 'string' && isAbsolute(root))
    : []
  const restored = []
  const conflicts = []
  const skipped = []

  for (const item of manifest.items) {
    const target = item?.path
    if (typeof target !== 'string' || !isAbsolute(target)) {
      skipped.push({ path: String(target), reason: 'not an absolute path' })
      continue
    }
    if (!force && roots.length > 0 && !roots.some((root) => isUnder(target, root))) {
      skipped.push({ path: target, reason: 'outside the recorded workspace roots' })
      continue
    }
    if (item.kind === 'dir') {
      if (!dryRun) {
        await mkdir(target, { recursive: true })
        if (Number.isFinite(item.mtimeMs)) {
          await utimes(target, new Date(item.mtimeMs), new Date(item.mtimeMs)).catch(() => {})
        }
      }
      restored.push(target)
      continue
    }
    if (item.kind !== 'file') {
      skipped.push({ path: target, reason: `unsupported item kind ${String(item.kind)}` })
      continue
    }
    const data = byName.get(item.entry)
    if (data === undefined) {
      skipped.push({ path: target, reason: `archive entry ${String(item.entry)} is missing` })
      continue
    }
    const existing = await lstat(target).catch(() => undefined)
    if (existing !== undefined && !force) {
      conflicts.push(target)
      continue
    }
    if (existing !== undefined && (existing.isSymbolicLink() || !existing.isFile())) {
      skipped.push({ path: target, reason: 'target is not a regular file' })
      continue
    }
    if (!dryRun) {
      await mkdir(dirname(target), { recursive: true })
      const mode = Number.isInteger(item.mode) ? item.mode & 0o777 : 0o600
      await writeFile(target, data, { mode })
      if (Number.isFinite(item.mtimeMs)) {
        await utimes(target, new Date(item.mtimeMs), new Date(item.mtimeMs)).catch(() => {})
      }
    }
    restored.push(target)
  }

  return { id: record.id, restored, conflicts, skipped, dryRun }
}

/**
 * Delete archives older than `days` (or all of them).
 *
 * @param {string} dir
 * @param {{ days?: number, all?: boolean }} options
 */
export async function purgeOld(dir, options = {}) {
  const storeDir = expandHome(dir)
  const all = options.all === true
  const days = Number.isFinite(options.days) ? options.days : 14
  const cutoff = all ? Number.POSITIVE_INFINITY : Date.now() - days * 24 * 60 * 60 * 1000
  let removed = 0
  let bytes = 0

  const children = await readdir(storeDir, { withFileTypes: true }).catch(() => [])
  for (const child of children) {
    if (!child.isDirectory() || !/^\d{8}$/.test(child.name)) continue
    const dayDir = join(storeDir, child.name)
    for (const file of await readdir(dayDir, { withFileTypes: true }).catch(() => [])) {
      if (!file.isFile() || !file.name.endsWith('.zip')) continue
      const path = join(dayDir, file.name)
      const info = await stat(path).catch(() => undefined)
      if (info === undefined) continue
      if (all || info.mtimeMs < cutoff) {
        if (await unlink(path).then(() => true, () => false)) {
          removed += 1
          bytes += info.size
        }
      }
    }
  }
  return { removed, bytes }
}
