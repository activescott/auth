import { useId, type ReactNode } from "react"
import type { LinkFlow, SignInMethod } from "../page-loaders.js"
import type { AddableSignInMethod } from "./add-sign-in-method.js"
import { AddSignInMethod, methodNoun } from "./add-sign-in-method.js"
import type {
  ProfileLinkComponent,
  ProfilePresentationProps,
} from "./profile-chrome.js"
import { Notice, ProfileCard, ProfileLink } from "./profile-chrome.js"
import type { ProfileStyler } from "./profile-styles.js"
import { createStyler } from "./profile-styles.js"
import { formatProfileDate } from "./format-date.js"

const DEFAULT_PROFILE_PATH = "/profile"
const DEFAULT_AUTH_BASE_PATH = "/auth"
/** Digits the email and sms providers issue by default (`otp.length`) */
const DEFAULT_CODE_LENGTH = 6

export interface SignInMethodsProps extends ProfilePresentationProps {
  /** `identities` from `profileAuthLoader`: everything but passkeys */
  identities: SignInMethod[]
  /** `linkFlow` from `profileAuthLoader` */
  linkFlow: LinkFlow
  /**
   * Which providers the block offers to add, in the order the links appear.
   * Empty (the default) lists the account's sign-in methods without offering
   * to add one. A provider the account already uses is dropped from the offer
   * unless the entry sets `allowMultiple`.
   */
  addMethods?: AddableSignInMethod[]
  /** Path of the page this block renders on (default "/profile") */
  profilePath?: string
  /** Where the auth routes are mounted (default "/auth") */
  authBasePath?: string
  /**
   * Offer to merge when a verified identifier turns out to belong to another
   * account (default false, which reports it as an error instead). Only turn
   * this on where `UserStore.onMerge` actually merges; a store that throws
   * would leave the user pressing a button that always fails.
   */
  allowMerge?: boolean
  /**
   * Replaces the description in the merge offer, for an application that has
   * to say what happens to the other account's data.
   */
  mergeDescription?: ReactNode
  /** Digits in the one-time code, matching the provider's `otp.length` (default 6) */
  codeLength?: number
  /** Block heading (default "Sign-in methods") */
  title?: string
}

/**
 * The email addresses and phone numbers that sign in to the account, and the
 * flow that adds another. Passkeys are listed separately by {@link Passkeys}.
 *
 * @example
 * ```tsx
 * <SignInMethods
 *   identities={loaderData.identities}
 *   linkFlow={loaderData.linkFlow}
 *   addMethods={[{ provider: "email" }, { provider: "sms", callingCode: "+1" }]}
 *   linkComponent={Link}
 * />
 * ```
 */
export function SignInMethods({
  identities,
  linkFlow,
  addMethods = [],
  profilePath = DEFAULT_PROFILE_PATH,
  authBasePath = DEFAULT_AUTH_BASE_PATH,
  allowMerge = false,
  mergeDescription,
  codeLength = DEFAULT_CODE_LENGTH,
  title = "Sign-in methods",
  classNames,
  includeDefaultStyles = true,
  linkComponent,
}: SignInMethodsProps) {
  const ui = createStyler(classNames, includeDefaultStyles)
  const conflict = linkFlow.conflict?.provider ?? null
  // The conflict message and the plain error are the same thing to the reader:
  // what went wrong with the identifier they just gave. Only one renders, so
  // they share the id the form's input points `aria-describedby` at.
  const errorId = useId()
  const errorMessage = conflict
    ? `That ${methodNoun(conflict, addMethods)} already signs in to another account.`
    : linkFlow.error

  return (
    <ProfileCard title={title} ui={ui} testId="sign-in-methods">
      {identities.length === 0 ? (
        <p className={ui.className("muted")} style={ui.style("muted")}>
          No email address or phone number signs in to this account yet.
        </p>
      ) : (
        <div
          className={ui.className("tableWrapper")}
          style={ui.style("tableWrapper")}
        >
          <table className={ui.className("table")} style={ui.style("table")}>
            <thead>
              <tr>
                <th className={ui.className("th")} style={ui.style("th")}>
                  Type
                </th>
                <th className={ui.className("th")} style={ui.style("th")}>
                  Identifier
                </th>
                <th className={ui.className("th")} style={ui.style("th")}>
                  Added
                </th>
              </tr>
            </thead>
            <tbody>
              {identities.map((identity) => (
                <tr key={identity.id} data-testid="sign-in-method">
                  <td className={ui.className("td")} style={ui.style("td")}>
                    {identity.provider}
                  </td>
                  <td className={ui.className("td")} style={ui.style("td")}>
                    {identity.identifier}
                  </td>
                  <td className={ui.className("td")} style={ui.style("td")}>
                    {formatProfileDate(identity.createdAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {linkFlow.merged && (
        <Notice tone="success" ui={ui} testId="merge-success">
          Accounts merged. The other account&apos;s sign-in methods now open
          this account.
        </Notice>
      )}

      {linkFlow.linked && (
        <Notice tone="success" ui={ui} testId="link-success">
          Sign-in method added. You can sign in with it now.
        </Notice>
      )}

      {/* After a merge the URL still carries the add-flow parameters, so the
          merged notice replaces the flow rather than stacking on it. */}
      {conflict && allowMerge ? (
        <MergePrompt
          provider={conflict}
          noun={methodNoun(conflict, addMethods)}
          description={mergeDescription}
          profilePath={profilePath}
          authBasePath={authBasePath}
          ui={ui}
          linkComponent={linkComponent}
        />
      ) : linkFlow.merged ? null : (
        <>
          {/* A conflict an application will not merge is still correctable:
              the address may have been mistyped into someone else's. The form
              stays below the message so there is a way to try again. */}
          {errorMessage && (
            <Notice tone="error" ui={ui} id={errorId} testId="link-error">
              Error: {errorMessage}
            </Notice>
          )}
          <AddSignInMethod
            methods={addMethods}
            identities={identities}
            linkFlow={linkFlow}
            profilePath={profilePath}
            authBasePath={authBasePath}
            codeLength={codeLength}
            errorId={errorMessage ? errorId : undefined}
            ui={ui}
            linkComponent={linkComponent}
          />
        </>
      )}
    </ProfileCard>
  )
}

interface MergePromptProps {
  provider: string
  noun: string
  description?: ReactNode
  profilePath: string
  authBasePath: string
  ui: ProfileStyler
  linkComponent?: ProfileLinkComponent
}

/**
 * Offered when a verify proved possession of an identifier that belongs to
 * another account. Posting to link-merge redeems the single-use merge ticket
 * the failed verify minted, which is bound to this browser by cookie; the core
 * re-checks the session and the identifier's owner before merging.
 */
function MergePrompt({
  provider,
  noun,
  description,
  profilePath,
  authBasePath,
  ui,
  linkComponent,
}: MergePromptProps) {
  // The explanation is what gets announced; the buttons below it are the
  // reader's to find, not to have read at them.
  return (
    <Notice tone="warning" ui={ui} testId="merge-prompt" role={null}>
      <p role="alert">
        {description ?? (
          <>
            That {noun} already opens a different account. You just proved it is
            yours, so you can merge that account into this one: its sign-in
            methods will open this account, and the other account is then gone.
            Merging cannot be undone.
          </>
        )}
      </p>
      <form method="post" action={`${authBasePath}/${provider}/link-merge`}>
        <div className={ui.className("actions")} style={ui.style("actions")}>
          <button
            type="submit"
            className={ui.className("mergeButton")}
            style={ui.style("mergeButton")}
          >
            Merge accounts
          </button>
          <ProfileLink
            to={profilePath}
            slot="cancelButton"
            ui={ui}
            linkComponent={linkComponent}
          >
            Cancel
          </ProfileLink>
        </div>
      </form>
    </Notice>
  )
}
