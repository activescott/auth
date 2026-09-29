/**
 * Ceremony options fetched before the user taps, so the tap can reach
 * navigator.credentials.get or create without awaiting anything. Safari
 * shows the passkey sheet only while the tap is still being handled; a fetch
 * awaited in between fails the ceremony with NotAllowedError.
 *
 * Every options response replaces the challenge cookie, which holds one
 * challenge. So this never starts a fetch while one is in flight, and does
 * not refresh while a modal ceremony is open.
 */
export interface PreparedOptions<T> {
  /**
   * Fetch options now and again every `maxAge`, until the returned function
   * is called. Calls may overlap (React StrictMode mounts twice); the
   * refreshes run while any of them is active.
   */
  prepare(): () => void
  /**
   * Run a modal ceremony with options for one attempt. When prepared options
   * are ready, `ceremony` is called before this returns, in the same task as
   * the caller; otherwise after the in-flight or a new fetch. Each challenge
   * is single-use, so while preparing, options are fetched again when the
   * attempt fails, or also when it succeeds if `refetchOnSuccess`.
   */
  runModal<R>(
    ceremony: (options: T) => Promise<R>,
    refetchOnSuccess: boolean,
  ): Promise<R>
  /**
   * Run a conditional (autofill) ceremony. It uses the prepared options
   * without taking them: the modal ceremony that aborts it can reuse the same
   * challenge, since neither has posted it yet.
   */
  runConditional<R>(ceremony: (options: T) => Promise<R>): Promise<R>
}

/**
 * Options from `fetchOptions`, prepared ahead of the tap and treated as
 * stale after `maxAge` milliseconds
 */
export function createPreparedOptions<T>(
  fetchOptions: () => Promise<T>,
  maxAge: number,
): PreparedOptions<T> {
  let prepared: { options: T; fetchedAt: number } | null = null
  let inFlight: Promise<T> | null = null
  let modalsPending = 0
  let preparers = 0
  let timer: ReturnType<typeof setTimeout> | undefined

  function fetchShared(): Promise<T> {
    inFlight ??= fetchOptions()
      .then((options) => {
        prepared = { options, fetchedAt: Date.now() }
        return options
      })
      .finally(() => {
        inFlight = null
      })
    return inFlight
  }

  function prefetch(): void {
    fetchShared().catch(() => {
      // The tap fetches again and shows the error if this keeps failing
    })
  }

  function refetchIfPreparing(): void {
    if (preparers > 0 && modalsPending === 0) prefetch()
  }

  /** Fresh prepared options, or null while a fetch will replace them */
  function ready(): T | null {
    return !inFlight && prepared && Date.now() - prepared.fetchedAt < maxAge
      ? prepared.options
      : null
  }

  function refresh(): void {
    if (modalsPending === 0) prefetch()
    timer = setTimeout(refresh, maxAge)
  }

  return {
    prepare() {
      preparers += 1
      if (preparers === 1) {
        if (ready() === null) prefetch()
        timer = setTimeout(refresh, maxAge)
      }
      let stopped = false
      return () => {
        if (stopped) return
        stopped = true
        preparers -= 1
        if (preparers === 0) clearTimeout(timer)
      }
    },

    async runModal(ceremony, refetchOnSuccess) {
      modalsPending += 1
      try {
        // No await when options are ready: the ceremony has to start while
        // the tap is still being handled
        const options = ready() ?? (await fetchShared())
        prepared = null
        const result = await ceremony(options)
        modalsPending -= 1
        if (refetchOnSuccess) refetchIfPreparing()
        return result
      } catch (error) {
        modalsPending -= 1
        refetchIfPreparing()
        throw error
      }
    },

    async runConditional(ceremony) {
      const options = ready() ?? (await fetchShared())
      try {
        return await ceremony(options)
      } finally {
        // A modal ceremony that aborted this one took the options already.
        // Otherwise the server has, or may have, consumed the challenge.
        if (prepared?.options === options) {
          prepared = null
          refetchIfPreparing()
        }
      }
    },
  }
}
