import type { ReactNode } from "react"
import type { LinkFlow, SignInMethod } from "../page-loaders.js"
import type { PasskeyRegistrationClient } from "../client/use-register-passkey.js"
import type { AccountEntry } from "./account-summary.js"
import { AccountSummary } from "./account-summary.js"
import type { AddableSignInMethod } from "./add-sign-in-method.js"
import type { ProfilePasskey } from "./passkeys.js"
import { Passkeys } from "./passkeys.js"
import type { ProfilePresentationProps } from "./profile-chrome.js"
import { SignInMethods } from "./sign-in-methods.js"
import { createStyler } from "./profile-styles.js"

export interface ProfilePageProps extends ProfilePresentationProps {
  /** Page heading (default "Profile") */
  title?: string
  /** Shown in the account block as "Email" */
  email?: string | null
  /** Shown in the account block as "Member since" */
  memberSince?: string | Date | null
  /** Extra rows for the account block */
  accountEntries?: AccountEntry[]
  /** `identities` from `profileAuthLoader` */
  identities: SignInMethod[]
  /** `linkFlow` from `profileAuthLoader` */
  linkFlow: LinkFlow
  /** Which providers the sign-in methods block offers to add */
  addMethods?: AddableSignInMethod[]
  /** Path of this page (default "/profile") */
  profilePath?: string
  /** Where the auth routes are mounted (default "/auth") */
  authBasePath?: string
  /** Offer an account merge on a conflict (default false) */
  allowMerge?: boolean
  /** Digits in the one-time code, matching the provider's `otp.length` (default 6) */
  codeLength?: number
  /** `passkeys` from `profileAuthLoader`; the block is dropped without `passkeyClient` */
  passkeys?: ProfilePasskey[]
  /** The browser passkey client; leave it out on an app without passkeys */
  passkeyClient?: PasskeyRegistrationClient
  /** Reload the page's data once a passkey is added, e.g. `useRevalidator().revalidate` */
  onPasskeyRegistered?: () => unknown
  /** Rendered after the three blocks, for a sign-out button or a way back */
  children?: ReactNode
}

/**
 * The whole profile page: the account summary, the sign-in methods, and the
 * passkeys, in that order.
 *
 * An application that needs its own sections, or a different order, renders
 * {@link AccountSummary}, {@link SignInMethods} and {@link Passkeys} itself
 * instead; this composes nothing they do not export.
 *
 * @example
 * ```tsx
 * export default function Profile({ loaderData }: Route.ComponentProps) {
 *   const revalidator = useRevalidator()
 *   return (
 *     <ProfilePage
 *       {...loaderData}
 *       addMethods={[{ provider: "email" }]}
 *       passkeyClient={passkeys}
 *       onPasskeyRegistered={revalidator.revalidate}
 *       linkComponent={Link}
 *     />
 *   )
 * }
 * ```
 */
export function ProfilePage({
  title = "Profile",
  email,
  memberSince,
  accountEntries,
  identities,
  linkFlow,
  addMethods,
  profilePath,
  authBasePath,
  allowMerge,
  codeLength,
  passkeys,
  passkeyClient,
  onPasskeyRegistered,
  classNames,
  includeDefaultStyles = true,
  linkComponent,
  children,
}: ProfilePageProps) {
  const ui = createStyler(classNames, includeDefaultStyles)
  const presentation = { classNames, includeDefaultStyles, linkComponent }

  return (
    <div
      className={ui.className("container")}
      style={ui.style("container")}
      data-testid="profile-page"
    >
      <h1 className={ui.className("title")} style={ui.style("title")}>
        {title}
      </h1>

      <AccountSummary
        email={email}
        memberSince={memberSince}
        entries={accountEntries}
        {...presentation}
      />

      <SignInMethods
        identities={identities}
        linkFlow={linkFlow}
        addMethods={addMethods}
        profilePath={profilePath}
        authBasePath={authBasePath}
        allowMerge={allowMerge}
        codeLength={codeLength}
        {...presentation}
      />

      {passkeyClient && (
        <Passkeys
          passkeys={passkeys ?? []}
          client={passkeyClient}
          onRegistered={onPasskeyRegistered}
          {...presentation}
        />
      )}

      {children}
    </div>
  )
}
