/**
 * Per-session mutation budget.
 *
 * A mass edit is not a single bad decision; it is many ordinary decisions in a
 * row. The budget turns that pattern into one interruption: past the soft limit
 * the gate asks the human, past the hard limit it refuses. Counters live in a
 * rolling window so a long debugging session does not accumulate forever.
 *
 * @module dsh-hard-gate/state
 */

export class MutationBudget {
  #sessions = new WeakMap()
  #config

  constructor(config) {
    this.#config = config
  }

  /**
   * Charge one mutation and report the verdict.
   *
   * @param {object} session - the agent session.
   * @param {string} key - canonical target, or a `shell:<rule>` marker.
   * @returns {'ok' | 'ask' | 'deny'}
   */
  charge(session, key) {
    const now = Date.now()
    let state = this.#sessions.get(session)
    if (state === undefined || now - state.startedAt >= this.#config.windowMs) {
      state = { startedAt: now, count: 0, perFile: new Map() }
      this.#sessions.set(session, state)
    }

    state.count += 1
    const perFile = (state.perFile.get(key) ?? 0) + 1
    state.perFile.set(key, perFile)

    if (this.#config.hardLimit > 0 && state.count > this.#config.hardLimit) return 'deny'
    if (this.#config.perFileLimit > 0 && perFile > this.#config.perFileLimit) return 'ask'
    if (this.#config.softLimit > 0 && state.count > this.#config.softLimit) return 'ask'
    return 'ok'
  }

  /** @returns {{ count: number, windowMs: number } | undefined} */
  snapshot(session) {
    const state = this.#sessions.get(session)
    if (state === undefined) return undefined
    return { count: state.count, windowMs: this.#config.windowMs }
  }

  clear() {
    this.#sessions = new WeakMap()
  }
}
