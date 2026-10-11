import { watchChallengeCookie } from "./challenge-cookie.js"

/**
 * Ceremony options fetched before the user taps, so the tap can reach
 * navigator.credentials.get or create without awaiting anything. Safari
 * shows the passkey sheet only while the tap is still being handled; a fetch
 * awaited in between fails the ceremony with NotAllowedError.
 *
 * Every options response replaces the challenge cookie, which holds one
 * challenge. So this never starts a fetch while one is in flight, does not
 * refresh while a modal ceremony or an autofill request holding the options
 * is open, and drops the options when a fetch anywhere else on the origin
 * replaces the cookie. A hidden tab does not refresh; it refetches when
 * shown.
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
  fetchOptions: (issued: () => void) => Promise<T>,
  maxAge: number,
): PreparedOptions<T> {
  let prepared: { options: T; fetchedAt: number } | null = null
  let inFlight: Promise<T> | null = null
  let modalsPending = 0
  let preparers = 0
  let timer: ReturnType<typeof setTimeout> | undefined
  // Options pending autofill requests are bound to
  const autofills = new Set<T>()
  let replacements = 0
  const cookie = watchChallengeCookie(() => {
    replacements += 1
    prepared = null
  })

  function fetchShared(): Promise<T> {
    inFlight ??= fetchAndKeep().finally(() => {
      inFlight = null
    })
    return inFlight
  }

  async function fetchAndKeep(): Promise<T> {
    let issuedAt: number | undefined
    const options = await fetchOptions(() => {
      cookie.replaced()
      issuedAt = replacements
    })
    // Keep them unless someone replaced the cookie after it was set
    if (issuedAt === replacements) {
      prepared = { options, fetchedAt: Date.now() }
    }
    return options
  }

  function prefetch(): void {
    fetchShared().catch(() => {
      // The tap fetches again and shows the error if this keeps failing
    })
  }

  function refetchIfPreparing(): void {
    // A new cookie would strand the autofill request's challenge; a hidden
    // tab leaves the cookie to the visible one
    const autofillHolds = prepared !== null && autofills.has(prepared.options)
    if (preparers > 0 && modalsPending === 0 && !autofillHolds && !isHidden()) {
      prefetch()
    }
  }

  /** Fresh prepared options, or null while a fetch will replace them */
  function ready(): T | null {
    return !inFlight && prepared && Date.now() - prepared.fetchedAt < maxAge
      ? prepared.options
      : null
  }

  function refresh(): void {
    refetchIfPreparing()
    timer = setTimeout(refresh, maxAge)
  }

  function onVisibilityChange(): void {
    if (ready() === null) refetchIfPreparing()
  }

  return {
    prepare() {
      preparers += 1
      if (preparers === 1) {
        if (ready() === null) refetchIfPreparing()
        timer = setTimeout(refresh, maxAge)
        if (typeof document !== "undefined") {
          document.addEventListener("visibilitychange", onVisibilityChange)
        }
      }
      let stopped = false
      return () => {
        if (stopped) return
        stopped = true
        preparers -= 1
        if (preparers === 0) {
          clearTimeout(timer)
          if (typeof document !== "undefined") {
            document.removeEventListener("visibilitychange", onVisibilityChange)
          }
        }
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
      autofills.add(options)
      try {
        return await ceremony(options)
      } finally {
        autofills.delete(options)
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

function isHidden(): boolean {
  return (
    typeof document !== "undefined" && document.visibilityState === "hidden"
  )
}
