/**
 * The challenge cookie is one per origin and holds one challenge, so every
 * options response replaces the challenge of any options fetched before it,
 * in this tab or another. Each holder of prepared options watches the cookie
 * and drops its options when someone else replaces it.
 */
export interface ChallengeCookie {
  /**
   * Call when an options response arrives, before parsing it: the browser
   * has stored its cookie by then
   */
  replaced(): void
}

const CHANNEL_NAME = "auth-passkey-challenge"
const STORAGE_KEY = "auth-passkey-challenge"

const tabId = Math.random().toString(36).slice(2)
const holders = new Set<() => void>()
let channel: BroadcastChannel | null | undefined
let broadcasts = 0

/**
 * Watch the challenge cookie; `onReplaced` runs when another holder in this
 * tab, or any fetch in another tab, replaces it
 */
export function watchChallengeCookie(onReplaced: () => void): ChallengeCookie {
  holders.add(onReplaced)
  return {
    replaced() {
      for (const holder of holders) {
        if (holder !== onReplaced) holder()
      }
      broadcast()
    },
  }
}

function replacedElsewhere(): void {
  for (const holder of holders) holder()
}

function connect(): void {
  if (channel !== undefined) return
  if (typeof BroadcastChannel === "function") {
    channel = new BroadcastChannel(CHANNEL_NAME)
    channel.onmessage = replacedElsewhere
    return
  }
  channel = null
  // Browsers fire storage only in other tabs; the tab ID keeps a test (or
  // an odd browser) that fires it here from dropping this tab's own options
  if (typeof addEventListener !== "function") return
  addEventListener("storage", (event) => {
    if (
      event.key === STORAGE_KEY &&
      event.newValue !== null &&
      !event.newValue.startsWith(`${tabId}:`)
    ) {
      replacedElsewhere()
    }
  })
}

function broadcast(): void {
  connect()
  if (channel) {
    channel.postMessage(null)
    return
  }
  broadcasts += 1
  try {
    // The value has to change for other tabs to get a storage event
    localStorage.setItem(STORAGE_KEY, `${tabId}:${broadcasts}`)
  } catch {
    // Storage disabled: other tabs find out only when their verify fails
  }
}
