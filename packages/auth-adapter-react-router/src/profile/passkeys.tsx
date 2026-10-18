import type { ReactNode } from "react"
import type { PasskeyRegistrationClient } from "../client/use-register-passkey.js"
import { useRegisterPasskey } from "../client/use-register-passkey.js"
import type { ProfilePresentationProps } from "./profile-chrome.js"
import { Notice, ProfileCard } from "./profile-chrome.js"
import { createStyler, LIST_ITEM_DIVIDER } from "./profile-styles.js"
import { formatProfileDate } from "./format-date.js"
import type { RemovalFlow } from "../page-loaders.js"
import { PASSKEY_PROVIDER_ID } from "../page-loaders.js"
import { RemoveIdentityButton } from "./remove-identity.js"

/**
 * One passkey as the block lists it. `PasskeySummary` from
 * `@activescott/auth-provider-passkey` satisfies it, so `loaderData.passkeys`
 * goes straight in.
 */
export interface ProfilePasskey {
  /** WebAuthn credential id (base64url) */
  credentialId: string
  /** User-assigned label; the credential id is abbreviated when there is none */
  nickname?: string | null
  /** True for a passkey synced to a cloud keychain or password manager */
  synced?: boolean
  createdAt: string | Date
  lastUsedAt?: string | Date | null
}

export interface PasskeysProps extends ProfilePresentationProps {
  passkeys: ProfilePasskey[]
  /** Create it once, at module scope: `createPasskeyClient()` from `@activescott/auth-provider-passkey/browser` */
  client: PasskeyRegistrationClient
  /**
   * Called once a passkey is saved, to reload the page's data so it appears in
   * the list. In React Router that is `useRevalidator().revalidate`.
   */
  onRegistered?: () => unknown
  /**
   * Show a Remove button on each passkey (default false). Needs
   * `@activescott/auth` 5.9.0 or later, which serves the unlink endpoint the
   * button posts to. The server keeps a passkey-only account from being
   * stranded, and refuses the passkey this session signed in with.
   */
  allowRemove?: boolean
  /** `removal` from `profileAuthLoader`, to report what a Remove did */
  removal?: RemovalFlow
  /** Where the auth routes are mounted (default "/auth") */
  authBasePath?: string
  /** Block heading (default "Passkeys") */
  title?: string
  /** Paragraph under the heading; pass null for none */
  description?: ReactNode
}

const DEFAULT_DESCRIPTION =
  "Sign in with Touch ID, Face ID, Windows Hello, or your password manager instead of waiting for a code."

const CREDENTIAL_ID_PREFIX_LENGTH = 8

function abbreviateCredentialId(credentialId: string): string {
  return `Passkey ${credentialId.slice(0, CREDENTIAL_ID_PREFIX_LENGTH)}…`
}

function passkeyName(passkey: ProfilePasskey): string {
  return passkey.nickname ?? abbreviateCredentialId(passkey.credentialId)
}

/**
 * The user's passkeys and the button that adds another. Registration runs in
 * the browser through the passkey client you pass, so an application without
 * passkeys never installs the WebAuthn library.
 *
 * @example
 * ```tsx
 * const revalidator = useRevalidator()
 * <Passkeys
 *   passkeys={loaderData.passkeys}
 *   client={passkeys}
 *   onRegistered={revalidator.revalidate}
 * />
 * ```
 */
export function Passkeys({
  passkeys,
  client,
  onRegistered,
  allowRemove = false,
  removal,
  authBasePath = "/auth",
  title = "Passkeys",
  description = DEFAULT_DESCRIPTION,
  classNames,
  includeDefaultStyles = true,
}: PasskeysProps) {
  const ui = createStyler(classNames, includeDefaultStyles)
  const registration = useRegisterPasskey({ client, onRegistered })
  const itemStyle = ui.style("listItem")
  const ownRemoval = removal?.provider === PASSKEY_PROVIDER_ID ? removal : null

  return (
    <ProfileCard title={title} ui={ui} testId="passkeys">
      {description === null ? null : (
        <p
          className={ui.className("description")}
          style={ui.style("description")}
        >
          {description}
        </p>
      )}

      {passkeys.length > 0 && (
        <ul className={ui.className("list")} style={ui.style("list")}>
          {passkeys.map((passkey, index) => (
            <li
              key={passkey.credentialId}
              data-testid="passkey-item"
              className={ui.className("listItem")}
              style={
                itemStyle && index > 0
                  ? { ...itemStyle, ...LIST_ITEM_DIVIDER }
                  : itemStyle
              }
            >
              <span
                className={ui.className("itemName")}
                style={ui.style("itemName")}
                title={passkey.credentialId}
              >
                {passkeyName(passkey)}
              </span>
              <small
                className={ui.className("itemDetail")}
                style={ui.style("itemDetail")}
              >
                {passkey.synced ? "synced" : "device-bound"} · added{" "}
                {formatProfileDate(passkey.createdAt)}
                {passkey.lastUsedAt &&
                  ` · last used ${formatProfileDate(passkey.lastUsedAt)}`}
              </small>
              {allowRemove && (
                <RemoveIdentityButton
                  provider={PASSKEY_PROVIDER_ID}
                  identifier={passkey.credentialId}
                  label={passkeyName(passkey)}
                  authBasePath={authBasePath}
                  ui={ui}
                />
              )}
            </li>
          ))}
        </ul>
      )}

      <button
        type="button"
        data-testid="add-passkey"
        className={ui.className("addButton")}
        style={ui.style("addButton")}
        onClick={() => void registration.register()}
        disabled={registration.status === "pending"}
      >
        {passkeys.length > 0 ? "Add another passkey" : "Add a passkey"}
      </button>

      {ownRemoval?.removed && (
        <Notice tone="success" ui={ui} testId="passkey-removed">
          Passkey removed. Your device or password manager may still offer it;
          delete it there too.
        </Notice>
      )}
      {ownRemoval?.error && (
        <Notice tone="error" ui={ui} testId="passkey-remove-error">
          Error: {ownRemoval.error}
        </Notice>
      )}

      {registration.status === "added" && (
        <Notice tone="success" ui={ui} testId="passkey-added">
          Passkey added.
        </Notice>
      )}
      {registration.status === "error" && (
        <Notice tone="error" ui={ui} testId="passkey-error">
          Error: {registration.error}
        </Notice>
      )}
    </ProfileCard>
  )
}
