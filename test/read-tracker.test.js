import test from 'node:test'
import assert from 'node:assert/strict'
import { parseReadFooter, readCoverage, mergeCoverage, missingRanges, isFullyCovered, formatRanges } from '../lib/read-tracker.js'

test('parses the end-of-file footer, bare or inside the read envelope', () => {
  assert.deepEqual(parseReadFooter('1: a\n\n(End of file - total 12 lines)'), {
    complete: true,
    total: 12,
    start: 1,
    end: 12,
  })
  assert.deepEqual(
    parseReadFooter('<path>a.ts</path>\n<type>file</type>\n<content>\n1: a\n\n(End of file - total 12 lines)\n</content>'),
    { complete: true, total: 12, start: 1, end: 12 },
  )
})

test('parses partial windows and byte caps', () => {
  assert.deepEqual(
    parseReadFooter('<content>\n1: a\n\n(Showing lines 1-200 of 512. Use offset=201 to continue.)\n</content>'),
    { complete: false, start: 1, end: 200, total: 512 },
  )
  assert.deepEqual(parseReadFooter('(Output capped. Showing lines 1-80. Use offset=81 to continue.)'), {
    complete: false,
    start: 1,
    end: 80,
  })
})

test('a footer mid-text is not the end of the read', () => {
  assert.equal(parseReadFooter('(End of file - total 3 lines)\nmore text'), undefined)
})

test('unrecognised output is not a footer', () => {
  assert.equal(parseReadFooter('just some text'), undefined)
  assert.equal(parseReadFooter(''), undefined)
})

test('structured metadata is authoritative', () => {
  assert.deepEqual(
    readCoverage({ meta: { offset: 201, lines: [{ number: 201 }, { number: 202 }], totalLines: 512 } }),
    { complete: false, total: 512, start: 201, end: 202 },
  )
  assert.deepEqual(
    readCoverage({ meta: { offset: 1, lines: [{ number: 1 }, { number: 2 }], totalLines: 2 } }),
    { complete: true, total: 2, start: 1, end: 2 },
  )
  assert.deepEqual(
    readCoverage({ meta: { offset: 1, lines: [], totalLines: 0 } }),
    { complete: true, total: 0, start: 1, end: 0 },
    'an empty file is fully read',
  )
})

test('structured metadata is ignored when it is not a read window', () => {
  assert.equal(readCoverage({ content: 'x' }), undefined)
  assert.equal(readCoverage({ meta: { path: 'x', offset: 1, lines: [] } }), undefined, 'totalLines is required')
  assert.equal(readCoverage({ meta: { offset: 0, lines: [], totalLines: 3 } }), undefined, 'offset is 1-based')
})

test('coverage merges adjacent windows and keeps real gaps', () => {
  assert.deepEqual(mergeCoverage([], 1, 200), [[1, 200]])
  assert.deepEqual(mergeCoverage([[1, 200]], 201, 400), [[1, 400]])
  assert.deepEqual(mergeCoverage([[401, 600]], 1, 200), [[1, 200], [401, 600]])
  assert.deepEqual(mergeCoverage([[1, 100], [201, 300]], 101, 200), [[1, 300]])
  assert.deepEqual(mergeCoverage([[1, 50]], 10, 20), [[1, 50]], 'an overlapping window is absorbed')

  const input = [[1, 200]]
  mergeCoverage(input, 201, 400)
  assert.deepEqual(input, [[1, 200]], 'the caller keeps its own ranges')
})

test('completeness needs one range from line 1 to the end', () => {
  assert.equal(isFullyCovered([[1, 600]], 600), true)
  assert.equal(isFullyCovered([[1, 500]], 600), false)
  assert.equal(isFullyCovered([[2, 600]], 600), false)
  assert.equal(isFullyCovered([[1, 200], [401, 600]], 600), false)
  assert.equal(isFullyCovered([[1, 600]], undefined), false)
  assert.equal(isFullyCovered([[1, 1]], 0), true, 'an empty file has nothing to lose')
})

test('missing ranges name exactly the unseen lines', () => {
  assert.deepEqual(missingRanges([[1, 200], [401, 600]], 600), [[201, 400]])
  assert.deepEqual(missingRanges([[1, 200]], 600), [[201, 600]])
  assert.deepEqual(missingRanges([[1, 600]], 600), [])
  assert.deepEqual(missingRanges([], 600), [[1, 600]])
  assert.equal(formatRanges([[201, 400]]), 'lines 201-400')
  assert.equal(formatRanges([[7, 7]]), 'line 7')
  assert.equal(formatRanges([[3, 3], [9, 12]]), 'lines 3, 9-12')
})