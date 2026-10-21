/**
 * Read-completeness tracking for the full-view overwrite rule.
 *
 * `dsh-fs-observation-policy` authorizes a whole-file replacement after *any*
 * read of the file, including a windowed or byte-capped one. This tracker keeps
 * the stronger fact the gate needs: did the session actually see the file to
 * EOF, and at which version?
 *
 * Two sources, in order:
 *  1. `result.meta` from the read tool's `presentationMeta` — structured,
 *     exact, and what the UI renders (`{ path, offset, lines, totalLines }`).
 *  2. The rendered footer inside `<content>` — a fallback for older/other read
 *     tools, tolerant of the envelope's closing tag.
 *
 * @module dsh-hard-gate/read-tracker
 */

/** The read envelope ends with `</content>`; both shapes must parse. */
const ENVELOPE_TAIL = String.raw`\s*(?:<\/content>\s*)?$`

const EOF_FOOTER = new RegExp(String.raw`\(End of file - total (\d+) lines\)` + ENVELOPE_TAIL)
const CAPPED_FOOTER = new RegExp(String.raw`\(Output capped\. Showing lines (\d+)-(\d+)\. Use offset=\d+ to continue\.\)` + ENVELOPE_TAIL)
const WINDOW_FOOTER = new RegExp(String.raw`\(Showing lines (\d+)-(\d+) of (\d+)\. Use offset=\d+ to continue\.\)` + ENVELOPE_TAIL)

/**
 * @typedef {object} ReadCoverage
 * @property {boolean} complete - whether the window reached the last line.
 * @property {number} [total] - total lines in the file.
 * @property {number} [start] - first line number in the window.
 * @property {number} [end] - last line number in the window.
 */

/**
 * Derive coverage from the read tool's structured presentation metadata.
 * Carries no heuristics: the last windowed line is compared with `totalLines`.
 *
 * @param {object} result - the `tools/result` payload.
 * @returns {ReadCoverage | undefined} `undefined` when the payload is not a read.
 */
export function readCoverage(result) {
  const meta = result?.meta
  if (meta === null || typeof meta !== 'object') return undefined
  if (!Number.isInteger(meta.totalLines) || meta.totalLines < 0) return undefined
  if (!Number.isInteger(meta.offset) || meta.offset < 1) return undefined
  if (!Array.isArray(meta.lines)) return undefined

  const last = meta.lines.at(-1)?.number
  const end = typeof last === 'number' ? last : meta.offset - 1
  const complete = meta.lines.length === 0 ? meta.totalLines === 0 : last === meta.totalLines

  return { complete, total: meta.totalLines, start: meta.offset, end }
}

/**
 * Parse the footer the `read` tool appends to its rendered result.
 *
 * @param {string} text - the tool result text.
 * @returns {ReadCoverage | undefined} `undefined` when no footer is recognisable.
 */
export function parseReadFooter(text) {
  const value = String(text ?? '')

  const eof = EOF_FOOTER.exec(value)
  if (eof !== null) {
    const total = Number(eof[1])
    return { complete: true, total, start: 1, end: total }
  }

  const capped = CAPPED_FOOTER.exec(value)
  if (capped !== null) return { complete: false, start: Number(capped[1]), end: Number(capped[2]) }

  const windowed = WINDOW_FOOTER.exec(value)
  if (windowed !== null) {
    return {
      complete: false,
      start: Number(windowed[1]),
      end: Number(windowed[2]),
      total: Number(windowed[3]),
    }
  }

  return undefined
}

/** Flatten a tool result's text content, tolerating every shape the seam allows. */
export function textOf(result) {
  if (typeof result === 'string') return result
  const content = result?.content
  if (typeof content === 'string') return content
  if (Array.isArray(content)) {
    return content
      .map((block) => (block !== null && typeof block === 'object' && block.type === 'text' && typeof block.text === 'string' ? block.text : ''))
      .join('\n')
  }
  if (typeof result?.text === 'string') return result.text
  return ''
}

/**
 * Add one read window to an already-covered range list and merge overlaps and
 * adjacency, so reading 1-200 then 201-400 counts as one continuous range while
 * reading 1-200 then 401-600 keeps the 201-400 gap.
 *
 * @param {[number, number][]} ranges - sorted, merged ranges.
 * @param {number} [start] - first line of the window.
 * @param {number} [end] - last line of the window.
 * @returns {[number, number][]} a new merged list.
 */
export function mergeCoverage(ranges, start, end) {
  const first = typeof start === 'number' && start > 0 ? start : 1
  const last = typeof end === 'number' ? Math.max(end, first) : first
  const merged = []
  for (const range of ranges.concat([[first, last]]).sort((left, right) => left[0] - right[0])) {
    const tail = merged.at(-1)
    if (tail !== undefined && range[0] <= tail[1] + 1) {
      tail[1] = Math.max(tail[1], range[1])
    } else {
      merged.push([range[0], range[1]])
    }
  }
  return merged
}

/**
 * Whether the ranges cover the file from line 1 through `total` with no gap.
 *
 * @param {[number, number][]} ranges
 * @param {number | undefined} total
 */
export function isFullyCovered(ranges, total) {
  if (typeof total !== 'number' || total < 0) return false
  if (ranges.length === 0) return false
  if (total === 0) return true
  return ranges[0][0] === 1 && ranges[0][1] >= total
}

/**
 * Gaps between the covered ranges and `total`, as inclusive line ranges.
 *
 * @param {[number, number][]} ranges
 * @param {number | undefined} total
 * @returns {[number, number][]}
 */
export function missingRanges(ranges, total) {
  if (typeof total !== 'number' || total <= 0) return []
  const missing = []
  let cursor = 1
  for (const [start, end] of ranges) {
    if (start > cursor) missing.push([cursor, Math.min(start - 1, total)])
    cursor = Math.max(cursor, end + 1)
    if (cursor > total) break
  }
  if (cursor <= total) missing.push([cursor, total])
  return missing
}

/** Render missing ranges as `lines 12-40, 90` for a model-facing explanation. */
export function formatRanges(ranges) {
  const parts = ranges.map(([start, end]) => (start === end ? String(start) : `${start}-${end}`))
  return `${parts.length === 1 && ranges[0][0] === ranges[0][1] ? 'line' : 'lines'} ${parts.join(', ')}`
}

/**
 * Per-session observed-read records, keyed by canonical target.
 *
 * A record is `{ complete, total?, start?, end?, mtimeMs?, size?, at }`.
 * Records are a derived cache: losing one only causes a re-read, never a write.
 */
export class ReadTracker {
  #sessions = new WeakMap()

  /** @param {object} session @param {string} key @param {object} record */
  record(session, key, record) {
    let byTarget = this.#sessions.get(session)
    if (byTarget === undefined) {
      byTarget = new Map()
      this.#sessions.set(session, byTarget)
    }
    byTarget.set(key, record)
  }

  /** @param {object} session @param {string} key */
  get(session, key) {
    return this.#sessions.get(session)?.get(key)
  }

  /** @param {object} session @param {string} key */
  forget(session, key) {
    this.#sessions.get(session)?.delete(key)
  }

  clear() {
    this.#sessions = new WeakMap()
  }
}
