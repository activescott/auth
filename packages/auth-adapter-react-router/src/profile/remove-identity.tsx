import type { ProfileStyler } from "./profile-styles.js"

export interface RemoveIdentityButtonProps {
  /** Provider of the identity, which names the unlink endpoint */
  provider: string
  /** The identity's identifier: an address, a number, a credential id */
  identifier: string
  /** What the button removes, for screen readers ("me@example.com") */
  label: string
  authBasePath: string
  ui: ProfileStyler
}

/**
 * A one-button form that posts the identifier to the provider's unlink
 * endpoint. A document POST, like the add-a-method forms, so the outcome comes
 * back as `?removed=` or `?removeError=` on this page. The server decides
 * whether the removal is allowed; refusing the last way into the account, or
 * the method this session signed in with, is its job and not the button's.
 */
export function RemoveIdentityButton({
  provider,
  identifier,
  label,
  authBasePath,
  ui,
}: RemoveIdentityButtonProps) {
  return (
    <form
      method="post"
      action={`${authBasePath}/${provider}/unlink`}
      style={{ display: "inline", margin: 0 }}
    >
      <input type="hidden" name="identifier" value={identifier} />
      <button
        type="submit"
        data-testid="remove-identity"
        aria-label={`Remove ${label}`}
        className={ui.className("removeButton")}
        style={ui.style("removeButton")}
      >
        Remove
      </button>
    </form>
  )
}
