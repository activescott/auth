import { Fragment, type ReactNode } from "react"
import type { ProfilePresentationProps } from "./profile-chrome.js"
import { ProfileCard } from "./profile-chrome.js"
import { createStyler } from "./profile-styles.js"
import { formatProfileDate } from "./format-date.js"

/** One row of the account block */
export interface AccountEntry {
  label: string
  value: ReactNode
}

export interface AccountSummaryProps extends ProfilePresentationProps {
  /** Shown as "Email"; leave it out and the row is not rendered */
  email?: string | null
  /** Shown as "Member since", as a UTC calendar date */
  memberSince?: string | Date | null
  /**
   * Rows appended after the built-in ones, for whatever else the account has:
   * a handle, a plan, an approval status. Pass only `entries` and no `email` or
   * `memberSince` to control the whole list and its order.
   */
  entries?: AccountEntry[]
  /** Block heading (default "Account") */
  title?: string
}

/**
 * Who the signed-in user is: their email address, when they joined, and
 * whatever else the application adds through `entries`.
 *
 * @example
 * ```tsx
 * <AccountSummary
 *   email={user.email}
 *   memberSince={user.createdAt}
 *   entries={[{ label: "Handle", value: user.handle }]}
 * />
 * ```
 */
export function AccountSummary({
  email,
  memberSince,
  entries = [],
  title = "Account",
  classNames,
  includeDefaultStyles = true,
}: AccountSummaryProps) {
  const ui = createStyler(classNames, includeDefaultStyles)
  const rows: AccountEntry[] = [
    ...(email == null ? [] : [{ label: "Email", value: email }]),
    ...(memberSince == null
      ? []
      : [{ label: "Member since", value: formatProfileDate(memberSince) }]),
    ...entries,
  ]

  return (
    <ProfileCard title={title} ui={ui} testId="account-summary">
      <dl
        className={ui.className("definitionList")}
        style={ui.style("definitionList")}
      >
        {/* A Fragment rather than a wrapper element: both layouts need the
            term and the value as direct children of the list. The built-in
            grid places them itself, and Bootstrap's `dl.row` puts its column
            classes on them. */}
        {rows.map((row) => (
          <Fragment key={row.label}>
            <dt
              className={ui.className("definitionTerm")}
              style={ui.style("definitionTerm")}
            >
              {row.label}
            </dt>
            <dd
              className={ui.className("definitionValue")}
              style={ui.style("definitionValue")}
            >
              {row.value}
            </dd>
          </Fragment>
        ))}
      </dl>
    </ProfileCard>
  )
}
