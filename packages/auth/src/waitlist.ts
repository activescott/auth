import type {
  InitiateGate,
  InitiateGateDecision,
  InitiateGateInput,
} from "./initiate-gate.js"
import type { AuthLogger, IdentityStore, UserStore } from "./types.js"

/**
 * Where a user stands on the waitlist. The values match the `ApprovalStatus`
 * enums apps already keep on their user rows, so a store can pass its column
 * through unmapped.
 */
export type ApprovalStatus = "PENDING" | "APPROVED" | "BLOCKED"

/**
 * Reads and writes each user's {@link ApprovalStatus}. Applications implement
 * it over their own user table, usually a column next to the rest of the
 * user record.
 */
export interface ApprovalStore {
  /**
   * The user's status, or null when the user does not exist or has none
   * recorded. The waitlist treats null as not approved, so users who predate
   * the waitlist need a status (usually APPROVED) before it is turned on.
   */
  getApprovalStatus(userId: string): Promise<ApprovalStatus | null>
  /** Record the user's status */
  setApprovalStatus(userId: string, status: ApprovalStatus): Promise<void>
}

/**
 * What {@link WaitlistConfig.autoApprove} is told about a waiting user who is
 * trying to sign in.
 */
export interface AutoApproveInput extends InitiateGateInput {
  /** The waiting user, created by this initiate when `isNewUser` is true */
  userId: string
  /** True when the identifier had no account before this initiate */
  isNewUser: boolean
}

/**
 * Something admins should hear about: a new user joined the waitlist, or
 * `autoApprove` let a waiting user in without one.
 */
export interface WaitlistNotice {
  reason: "waitlisted" | "auto-approved"
  userId: string
  /** Provider the user is signing in with, e.g. "email" or "sms" */
  provider: string
  /** The normalized email address or phone number */
  identifier: string
}

/** Configuration for {@link createWaitlist} */
export interface WaitlistConfig {
  /** The same identity store `Auth` uses */
  identityStore: IdentityStore
  /** The same user store `Auth` uses */
  userStore: UserStore
  /** Where each user's approval status lives */
  approvalStore: ApprovalStore
  /** Where waiting users are sent instead of receiving a sign-in message */
  waitlistUrl: string
  /**
   * Where blocked users are sent. Defaults to `waitlistUrl`, so a blocked
   * user is not told they were blocked.
   */
  blockedUrl?: string
  /**
   * Application rules that let a waiting user in without an admin: an
   * allowlist of addresses, an invite someone already sent them. Called for
   * PENDING users only, never for BLOCKED ones, so no rule can undo a block.
   * Returning true approves the user and the sign-in proceeds.
   */
  autoApprove?: (input: AutoApproveInput) => boolean | Promise<boolean>
  /**
   * Called when a user joins the waitlist and when `autoApprove` lets
   * someone in. Filter on `notice.reason` for the ones you want. A throw is
   * logged and swallowed: the notice is about something that already
   * happened, and losing it must not fail the sign-in that caused it.
   */
  notify?: (notice: WaitlistNotice) => void | Promise<void>
  /** Where a failed `notify` is reported */
  logger?: AuthLogger
}

/** What {@link Waitlist.handleAdminAction} did */
export type WaitlistActionResult =
  | { success: true; userId: string; status: ApprovalStatus }
  | { success: false; error: string }

/**
 * A waitlist in front of sign-in. Pass it as `AuthConfig.gate`; it is an
 * {@link InitiateGate}.
 */
export interface Waitlist extends InitiateGate {
  /**
   * Decide one initiate: approved users proceed, blocked users go to
   * `blockedUrl`, waiting users go to `waitlistUrl` unless `autoApprove` lets
   * them in. An identifier with no account gets a PENDING user and its
   * identity here, so it shows up on the admin dashboard and the verify step
   * later finds the same user. Link initiates always proceed: they come from
   * a signed-in user, whose status the per-request check covers.
   */
  onInitiate(input: InitiateGateInput): Promise<InitiateGateDecision>
  /**
   * Where to send a signed-in user who may not use the app: null when they
   * are approved, otherwise `blockedUrl` or `waitlistUrl`. The initiate gate
   * does not cover passkey sign-ins or a status that changed after sign-in,
   * so call this on every request (e.g. from the React Router adapter's
   * `onSessionVerified`).
   */
  redirectFor(userId: string): Promise<string | null>
  /** Mark the user APPROVED */
  approve(userId: string): Promise<void>
  /** Mark the user BLOCKED */
  block(userId: string): Promise<void>
  /**
   * Apply an admin's approve or block from a posted form with a `userId`
   * field and an `intent` field of "approve" or "block", as rendered by the
   * admin dashboard's `rowActions`. Call it only after checking the caller is
   * an admin.
   */
  handleAdminAction(formData: FormData): Promise<WaitlistActionResult>
}

/**
 * Create a waitlist: identifiers without an approved account are sent to
 * `waitlistUrl` instead of being sent a code, admins are told through
 * `notify`, and approve/block decisions go through the {@link ApprovalStore}.
 */
export function createWaitlist(config: WaitlistConfig): Waitlist {
  const { identityStore, userStore, approvalStore, waitlistUrl } = config
  const blockedUrl = config.blockedUrl ?? waitlistUrl

  async function notify(notice: WaitlistNotice): Promise<void> {
    if (!config.notify) return
    try {
      await config.notify(notice)
    } catch (error) {
      config.logger?.warn("waitlist notify failed", {
        reason: notice.reason,
        userId: notice.userId,
        error: error instanceof Error ? error.message : String(error),
      })
    }
  }

  async function findOrCreateUser(
    provider: string,
    identifier: string,
  ): Promise<{ userId: string; isNewUser: boolean }> {
    const identity = await identityStore.findByProviderAndIdentifier(
      provider,
      identifier,
    )
    if (identity) return { userId: identity.userId, isNewUser: false }

    // The same two calls the verify step makes for an unknown identifier, so
    // verify finds this identity instead of creating a second user
    const user = await userStore.create({ provider, identifier })
    await identityStore.create({
      userId: user.id,
      provider,
      identifier,
      providerState: {},
    })
    return { userId: user.id, isNewUser: true }
  }

  async function setStatus(
    userId: string,
    status: ApprovalStatus,
  ): Promise<void> {
    await approvalStore.setApprovalStatus(userId, status)
  }

  return {
    async onInitiate(input) {
      if (input.mode === "link") return "allow"

      const { provider, identifier } = input
      const { userId, isNewUser } = await findOrCreateUser(provider, identifier)
      const status = isNewUser
        ? null
        : await approvalStore.getApprovalStatus(userId)

      if (status === "APPROVED") return "allow"
      if (status === "BLOCKED") return { redirect: blockedUrl }

      if (await config.autoApprove?.({ ...input, userId, isNewUser })) {
        await setStatus(userId, "APPROVED")
        await notify({ reason: "auto-approved", userId, provider, identifier })
        return "allow"
      }

      // Admins hear about a user once, when they join; repeat attempts from
      // someone already waiting stay quiet
      if (status !== "PENDING") {
        await setStatus(userId, "PENDING")
        await notify({ reason: "waitlisted", userId, provider, identifier })
      }
      return { redirect: waitlistUrl }
    },

    async redirectFor(userId) {
      const status = await approvalStore.getApprovalStatus(userId)
      if (status === "APPROVED") return null
      return status === "BLOCKED" ? blockedUrl : waitlistUrl
    },

    approve: (userId) => setStatus(userId, "APPROVED"),

    block: (userId) => setStatus(userId, "BLOCKED"),

    async handleAdminAction(formData) {
      const userId = formData.get("userId")
      if (typeof userId !== "string" || userId.length === 0) {
        return { success: false, error: "userId is required" }
      }
      const intent = formData.get("intent")
      if (intent !== "approve" && intent !== "block") {
        return { success: false, error: 'intent must be "approve" or "block"' }
      }
      const status = intent === "approve" ? "APPROVED" : "BLOCKED"
      await setStatus(userId, status)
      return { success: true, userId, status }
    },
  }
}
