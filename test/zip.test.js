import test from 'node:test'
import assert from 'node:assert/strict'
import { createZip, crc32, readZip } from '../lib/zip.js'

test('crc32 matches the standard check vector', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926)
})

test('zip round-trips text, binary, and non-ASCII names', async () => {
  const entries = [
    { name: 'src/hello.txt', data: Buffer.from('hello\nworld\n') },
    { name: '数据/文件.bin', data: Buffer.from([0, 1, 2, 255, 254]) },
    { name: 'empty.txt', data: Buffer.alloc(0) },
  ]
  const archive = await createZip(entries)
  assert.equal(archive.subarray(0, 4).toString('hex'), '504b0304')

  const read = await readZip(archive)
  assert.equal(read.length, 3)
  const byName = new Map(read.map((entry) => [entry.name, entry.data]))
  assert.equal(byName.get('src/hello.txt').toString('utf8'), 'hello\nworld\n')
  assert.deepEqual([...byName.get('数据/文件.bin')], [0, 1, 2, 255, 254])
  assert.equal(byName.get('empty.txt').length, 0)
})

test('zip preserves the mtime in the DOS timestamp', async () => {
  const mtime = new Date(2024, 4, 17, 13, 45, 20)
  const archive = await createZip([{ name: 'a.txt', data: Buffer.from('a'), mtime }])
  const read = await readZip(archive)
  assert.equal(read[0].name, 'a.txt')
  assert.equal(read[0].data.toString(), 'a')
})

test('a truncated archive is rejected', async () => {
  const archive = await createZip([{ name: 'a.txt', data: Buffer.from('hello') }])
  await assert.rejects(readZip(archive.subarray(0, 20)), /not a zip archive/)
})

test('a corrupted payload fails its CRC check', async () => {
  const archive = await createZip([{ name: 'a.txt', data: Buffer.from('the payload is long enough to be deflated') }])
  const broken = Buffer.from(archive)
  // Flip a byte inside the first local file's compressed data.
  broken[30 + 'a.txt'.length + 2] ^= 0xff
  await assert.rejects(readZip(broken), /CRC check|wrong size|incorrect header check|invalid/)
})
