#!/usr/bin/env node
/**
 * Command line for the hard-gate restore-point store.
 *
 *   node lib/restore.js list [--dir <store>] [--limit 20]
 *   node lib/restore.js restore <id|last> [--dir <store>] [--force] [--dry-run]
 *   node lib/restore.js purge [--dir <store>] [--days 14 | --all]
 *
 * The store directory defaults to `~/.dsh/hard-gate/backups`; pass `--dir` when
 * the plugin's `backupDir` was changed.
 *
 * @module dsh-hard-gate/restore
 */

import { stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { defaultBackupDir, purgeOld, readIndex, restoreRecord } from './backup.js'
import { expandHome } from './paths.js'

function usage() {
  return [
    'usage:',
    '  node lib/restore.js list [--dir <store>] [--limit 20]',
    '  node lib/restore.js restore <id|last> [--dir <store>] [--force] [--dry-run]',
    '  node lib/restore.js purge [--dir <store>] [--days 14 | --all]',
    '',
    `store: ${defaultBackupDir()}`,
  ].join('\n')
}

function parse(argv) {
  const options = { dir: defaultBackupDir(), limit: 20, days: 14, all: false, force: false, dryRun: false }
  const positional = []
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--dir') options.dir = expandHome(String(argv[++index] ?? ''))
    else if (argument.startsWith('--dir=')) options.dir = expandHome(argument.slice(6))
    else if (argument === '--limit') options.limit = positive(argv[++index], 20)
    else if (argument.startsWith('--limit=')) options.limit = positive(argument.slice(8), 20)
    else if (argument === '--days') options.days = positive(argv[++index], 14)
    else if (argument.startsWith('--days=')) options.days = positive(argument.slice(7), 14)
    else if (argument === '--all') options.all = true
    else if (argument === '--force') options.force = true
    else if (argument === '--dry-run') options.dryRun = true
    else if (argument === '-h' || argument === '--help') options.help = true
    else if (argument.startsWith('-')) throw new Error(`unknown option ${argument}`)
    else positional.push(argument)
  }
  return { options, positional }
}

function positive(value, fallback) {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? number : fallback
}

function bytes(value) {
  const number = Number(value) || 0
  if (number >= 1024 * 1024 * 1024) return `${(number / (1024 * 1024 * 1024)).toFixed(2)} GiB`
  if (number >= 1024 * 1024) return `${(number / (1024 * 1024)).toFixed(1)} MiB`
  if (number >= 1024) return `${(number / 1024).toFixed(1)} KiB`
  return `${number} B`
}

function when(value) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

async function list(options) {
  const records = await readIndex(options.dir)
  const alive = []
  for (const record of records) {
    if (typeof record.zip !== 'string') continue
    if (await stat(record.zip).then(() => true, () => false)) alive.push(record)
  }
  if (alive.length === 0) {
    process.stdout.write(`no restore points in ${options.dir}\n`)
    return 0
  }
  alive.sort((left, right) => String(right.at).localeCompare(String(left.at)))
  for (const record of alive.slice(0, options.limit)) {
    const files = typeof record.files === 'number' ? record.files : '?'
    process.stdout.write(`${record.id}  ${when(record.at)}  ${record.tool ?? '?'}/${record.rule ?? '?'}  ${files} file(s)  ${bytes(record.sourceBytes)} -> ${bytes(record.zipBytes)}${record.bin ? '  [recycle bin]' : ''}\n`)
  }
  process.stdout.write(`\nrestore with: node lib/restore.js restore <id> --dir "${options.dir}"\n`)
  return 0
}

function pick(records, wanted) {
  if (wanted === 'last') {
    return records.slice().sort((left, right) => String(right.at).localeCompare(String(left.at)))[0]
  }
  const exact = records.find((record) => record.id === wanted)
  if (exact !== undefined) return exact
  const matches = records.filter((record) => record.id.startsWith(wanted))
  if (matches.length === 1) return matches[0]
  if (matches.length > 1) throw new Error(`"${wanted}" matches ${matches.length} restore points; use a longer id`)
  return undefined
}

async function restore(options, wanted) {
  const records = await readIndex(options.dir)
  const record = pick(records, wanted)
  if (record === undefined) throw new Error(`restore point "${wanted}" not found in ${options.dir}`)
  let result
  try {
    result = await restoreRecord(record, { force: options.force, dryRun: options.dryRun })
  } catch (error) {
    if (error?.code === 'ENOENT') throw new Error(`restore point ${record.id} was pruned; its archive no longer exists`)
    throw error
  }
  const prefix = options.dryRun ? 'would restore' : 'restored'
  process.stdout.write(`${prefix} ${result.restored.length} item(s) from ${record.id}\n`)
  for (const path of result.restored) process.stdout.write(`  + ${path}\n`)
  if (result.conflicts.length > 0) {
    process.stdout.write(`\n${result.conflicts.length} target(s) already exist; re-run with --force to overwrite:\n`)
    for (const path of result.conflicts) process.stdout.write(`  = ${path}\n`)
  }
  if (result.skipped.length > 0) {
    process.stdout.write(`\n${result.skipped.length} item(s) skipped:\n`)
    for (const item of result.skipped) process.stdout.write(`  ! ${item.path} (${item.reason})\n`)
  }
  return result.conflicts.length === 0 && result.skipped.length === 0 ? 0 : 1
}

async function purge(options) {
  const result = await purgeOld(options.dir, { days: options.days, all: options.all })
  process.stdout.write(`removed ${result.removed} archive(s), ${bytes(result.bytes)} freed\n`)
  return 0
}

export async function main(argv = process.argv.slice(2)) {
  const { options, positional } = parse(argv)
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return 0
  }
  const command = positional[0] ?? 'list'
  if (command === 'list') return list(options)
  if (command === 'restore') {
    if (positional[1] === undefined) throw new Error(`restore needs an id (or "last")\n\n${usage()}`)
    return restore(options, positional[1])
  }
  if (command === 'purge') return purge(options)
  throw new Error(`unknown command "${command}"\n\n${usage()}`)
}

const invoked = process.argv[1] === undefined ? '' : pathToFileURL(resolve(process.argv[1])).href
const self = import.meta.url
const isMain = process.platform === 'win32' ? invoked.toLowerCase() === self.toLowerCase() : invoked === self
if (isMain) {
  main().then((code) => {
    process.exitCode = code
  }, (error) => {
    process.stderr.write(`hard-gate restore: ${error?.message ?? error}\n`)
    process.exitCode = 1
  })
}
