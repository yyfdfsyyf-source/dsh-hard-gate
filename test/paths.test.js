import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, realpath } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join, sep } from 'node:path'
import {
  canonicalTarget,
  isUnder,
  lexicalTarget,
  matchProtected,
  pathKey,
  stripExtended,
} from '../lib/paths.js'

test('strips the Win32 extended-length prefix', () => {
  assert.equal(stripExtended('\\\\?\\C:\\work\\a.txt'), 'C:\\work\\a.txt')
  assert.equal(stripExtended('\\\\?\\UNC\\server\\share\\a.txt'), '\\\\server\\share\\a.txt')
})

test('isUnder respects segment boundaries and the root itself', { skip: process.platform !== 'win32' }, () => {
  assert.equal(isUnder('D:\\work\\project\\src\\a.ts', 'D:\\work\\project'), true)
  assert.equal(isUnder('D:\\work\\project', 'D:\\work\\project'), true)
  assert.equal(isUnder('D:\\work\\project2\\a.ts', 'D:\\work\\project'), false)
  assert.equal(isUnder('D:\\work\\project\\..\\other', 'D:\\work\\project'), false, 'normalization happens first')
})

test('pathKey folds case on Windows only', () => {
  const key = pathKey('D:\\Work\\Project\\A.TS')
  if (process.platform === 'win32') assert.equal(key, 'd:\\work\\project\\a.ts')
  else assert.equal(key, 'D:\\Work\\Project\\A.TS')
})

test('matchProtected finds roots, segments, and file names', { skip: process.platform !== 'win32' }, () => {
  const rules = {
    roots: [pathKey('C:\\Windows'), pathKey(join(homedir(), '.ssh'))],
    segments: new Set(['.git']),
    basenames: new Set(['id_rsa']),
  }
  assert.equal(matchProtected(pathKey('C:\\Windows\\System32\\drivers\\etc\\hosts'), rules), pathKey('C:\\Windows'))
  assert.equal(matchProtected(pathKey('D:\\work\\project\\.git\\config'), rules), '.git')
  assert.equal(matchProtected(pathKey('D:\\work\\project\\keys\\id_rsa'), rules), 'id_rsa')
  assert.equal(matchProtected(pathKey(join(homedir(), '.ssh', 'id_rsa')), rules), pathKey(join(homedir(), '.ssh')))
  assert.equal(matchProtected(pathKey('D:\\work\\project\\src\\a.ts'), rules), undefined)
})

test('lexicalTarget expands ~ and resolves relative paths', { skip: process.platform !== 'win32' }, () => {
  assert.equal(lexicalTarget('D:\\work\\project', 'src\\a.ts'), 'D:\\work\\project\\src\\a.ts')
  assert.equal(lexicalTarget('D:\\work\\project', '~\\notes.txt'), join(homedir(), 'notes.txt'))
})

test('canonicalTarget resolves the deepest existing ancestor', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hard-gate-paths-'))
  const nested = join(dir, 'a', 'b')
  await mkdir(nested, { recursive: true })
  const real = await realpath(nested)
  const target = await canonicalTarget(dir, join('a', 'b', 'new.txt'))
  assert.equal(target, join(real, 'new.txt'))
})
