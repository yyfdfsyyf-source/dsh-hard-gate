/**
 * Minimal ZIP archive support for restore points.
 *
 * The gate must work in a linked checkout with no `node_modules`, so this file
 * uses only Node built-ins: `zlib` supplies raw DEFLATE and the CRC-32 table
 * below keeps the archive readable by Explorer, 7-Zip, and `Expand-Archive`.
 *
 * Only the subset the gate writes is supported: no ZIP64, no encryption, no
 * data descriptors, no multi-disk archives.
 *
 * @module dsh-hard-gate/zip
 */

import { deflateRaw, inflateRaw } from 'node:zlib'
import { promisify } from 'node:util'

const deflate = promisify(deflateRaw)
const inflate = promisify(inflateRaw)

const LOCAL_SIGNATURE = 0x04034b50
const CENTRAL_SIGNATURE = 0x02014b50
const EOCD_SIGNATURE = 0x06054b50
const UTF8_FLAG = 0x0800
const METHOD_STORE = 0
const METHOD_DEFLATE = 8
const MAX_ENTRIES = 0xffff
const ZIP64_SENTINEL = 0xffffffff
const MAX_UNCOMPRESSED = 256 * 1024 * 1024

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let index = 0; index < 256; index += 1) {
    let value = index
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    }
    table[index] = value >>> 0
  }
  return table
})()

/**
 * CRC-32 of a buffer, as ZIP requires.
 *
 * @param {Buffer} buffer
 * @returns {number} unsigned 32-bit checksum.
 */
export function crc32(buffer) {
  let value = 0xffffffff
  for (let index = 0; index < buffer.length; index += 1) {
    value = CRC_TABLE[(value ^ buffer[index]) & 0xff] ^ (value >>> 8)
  }
  return (value ^ 0xffffffff) >>> 0
}

/** MS-DOS date/time pair for a Date. */
function dosDateTime(value) {
  const date = value instanceof Date && !Number.isNaN(value.getTime()) ? value : new Date()
  const year = Math.min(Math.max(date.getFullYear(), 1980), 2107)
  return {
    time: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
  }
}

/**
 * Build a ZIP archive.
 *
 * @param {{ name: string, data: Buffer, mtime?: Date }[]} entries
 * @returns {Promise<Buffer>}
 */
export async function createZip(entries) {
  if (!Array.isArray(entries)) throw new TypeError('zip entries must be an array')
  if (entries.length > MAX_ENTRIES) throw new RangeError(`a zip cannot hold more than ${MAX_ENTRIES} entries`)

  const localParts = []
  const centralParts = []
  let offset = 0

  for (const entry of entries) {
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data ?? '')
    const name = Buffer.from(String(entry.name).replace(/\\/g, '/'), 'utf8')
    if (name.length === 0 || name.length > 0xffff) throw new RangeError('zip entry name is empty or too long')
    if (data.length >= ZIP64_SENTINEL) throw new RangeError('zip entry is too large (4 GiB limit)')

    const checksum = crc32(data)
    let method = METHOD_STORE
    let body = data
    if (data.length > 32) {
      const compressed = await deflate(data)
      if (compressed.length < data.length) {
        method = METHOD_DEFLATE
        body = compressed
      }
    }

    const stamp = dosDateTime(entry.mtime)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(LOCAL_SIGNATURE, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(UTF8_FLAG, 6)
    local.writeUInt16LE(method, 8)
    local.writeUInt16LE(stamp.time, 10)
    local.writeUInt16LE(stamp.date, 12)
    local.writeUInt32LE(checksum, 14)
    local.writeUInt32LE(body.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(CENTRAL_SIGNATURE, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(UTF8_FLAG, 8)
    central.writeUInt16LE(method, 10)
    central.writeUInt16LE(stamp.time, 12)
    central.writeUInt16LE(stamp.date, 14)
    central.writeUInt32LE(checksum, 16)
    central.writeUInt32LE(body.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt16LE(0, 30)
    central.writeUInt16LE(0, 32)
    central.writeUInt16LE(0, 34)
    central.writeUInt16LE(0, 36)
    central.writeUInt32LE(0, 38)
    central.writeUInt32LE(offset, 42)

    localParts.push(local, name, body)
    centralParts.push(central, name)
    offset += local.length + name.length + body.length
  }

  const centralSize = centralParts.reduce((total, part) => total + part.length, 0)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(EOCD_SIGNATURE, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(centralSize, 12)
  eocd.writeUInt32LE(offset, 16)
  eocd.writeUInt16LE(0, 20)

  return Buffer.concat([...localParts, ...centralParts, eocd])
}

/** Locate the end-of-central-directory record. */
function findEocd(buffer) {
  const minimum = Math.max(0, buffer.length - 22 - 0xffff)
  for (let index = buffer.length - 22; index >= minimum; index -= 1) {
    if (buffer.readUInt32LE(index) !== EOCD_SIGNATURE) continue
    if (index + 22 + buffer.readUInt16LE(index + 20) === buffer.length) return index
  }
  return -1
}

/**
 * Read a ZIP archive produced by {@link createZip} (or any ordinary store /
 * deflate archive without ZIP64).
 *
 * @param {Buffer} buffer
 * @returns {Promise<{ name: string, data: Buffer }[]>}
 */
export async function readZip(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) throw new Error('not a zip archive')
  const eocd = findEocd(buffer)
  if (eocd < 0) throw new Error('zip end-of-central-directory record not found')

  const count = buffer.readUInt16LE(eocd + 10)
  const centralSize = buffer.readUInt32LE(eocd + 12)
  const centralOffset = buffer.readUInt32LE(eocd + 16)
  if (count === 0xffff || centralSize === ZIP64_SENTINEL || centralOffset === ZIP64_SENTINEL) {
    throw new Error('ZIP64 archives are not supported')
  }
  if (centralOffset + centralSize > buffer.length) throw new Error('zip central directory lies outside the archive')

  const entries = []
  let cursor = centralOffset
  for (let index = 0; index < count; index += 1) {
    if (buffer.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) throw new Error('zip central directory is corrupt')
    const flags = buffer.readUInt16LE(cursor + 8)
    if ((flags & 0x0001) !== 0) throw new Error('encrypted zip entries are not supported')
    if ((flags & 0x0008) !== 0) throw new Error('zip data descriptors are not supported')

    const method = buffer.readUInt16LE(cursor + 10)
    const checksum = buffer.readUInt32LE(cursor + 16)
    const compressedSize = buffer.readUInt32LE(cursor + 20)
    const uncompressedSize = buffer.readUInt32LE(cursor + 24)
    const nameLength = buffer.readUInt16LE(cursor + 28)
    const extraLength = buffer.readUInt16LE(cursor + 30)
    const commentLength = buffer.readUInt16LE(cursor + 32)
    const localOffset = buffer.readUInt32LE(cursor + 42)
    const name = buffer.toString('utf8', cursor + 46, cursor + 46 + nameLength)
    if (uncompressedSize > MAX_UNCOMPRESSED) throw new Error(`zip entry ${JSON.stringify(name)} is too large to extract safely`)

    if (buffer.readUInt32LE(localOffset) !== LOCAL_SIGNATURE) throw new Error(`zip entry ${JSON.stringify(name)} has no local header`)
    const localNameLength = buffer.readUInt16LE(localOffset + 26)
    const localExtraLength = buffer.readUInt16LE(localOffset + 28)
    const dataStart = localOffset + 30 + localNameLength + localExtraLength
    if (dataStart + compressedSize > buffer.length) throw new Error(`zip entry ${JSON.stringify(name)} is truncated`)
    const body = buffer.subarray(dataStart, dataStart + compressedSize)

    let data
    if (method === METHOD_STORE) {
      data = Buffer.from(body)
    } else if (method === METHOD_DEFLATE) {
      data = await inflate(body, { maxOutputLength: MAX_UNCOMPRESSED })
    } else {
      throw new Error(`zip entry ${JSON.stringify(name)} uses unsupported compression method ${method}`)
    }
    if (data.length !== uncompressedSize) throw new Error(`zip entry ${JSON.stringify(name)} has the wrong size`)
    if (crc32(data) !== checksum) throw new Error(`zip entry ${JSON.stringify(name)} failed its CRC check`)

    entries.push({ name, data })
    cursor += 46 + nameLength + extraLength + commentLength
  }

  return entries
}
