import type { ComponentType, CSSProperties, ReactNode } from "react"
import type { ProfileClassNames, ProfileStyler } from "./profile-styles.js"

/**
 * A router-aware link component, e.g. React Router's `Link`. Pass one to get
 * client-side navigation for the add-a-sign-in-method links; omit it and the
 * blocks use plain anchors, which navigate the whole document.
 *
 * Typed structurally rather than imported from `react-router` on purpose: this
 * package imports nothing from the router, which is why one build serves both
 * v7 and v8.
 */
export type ProfileLinkComponent = ComponentType<{
  to: string
  className?: string
  style?: CSSProperties
  children: ReactNode
}>

/** Props every profile block accepts for appearance and navigation */
export interface ProfilePresentationProps {
  /**
   * Your own class for any slot you name. A slot you give a class to gets no
   * built-in styling, so your design system's rules are not competing with an
   * inline style they cannot outrank.
   */
  classNames?: ProfileClassNames
  /**
   * Apply the built-in look to slots you have not overridden (default true).
   * Set false to render structural markup only.
   */
  includeDefaultStyles?: boolean
  /** Router link component for client-side navigation */
  linkComponent?: ProfileLinkComponent
}

export interface ProfileLinkProps {
  to: string
  /** Styling slot to draw the class/style from; omit for an unstyled link */
  slot?: "addButton" | "cancelButton"
  ui: ProfileStyler
  linkComponent?: ProfileLinkComponent
  children: ReactNode
}

/**
 * Render a link through the supplied router component, or a plain anchor when
 * there is none.
 */
export function ProfileLink({
  to,
  slot,
  ui,
  linkComponent: Link,
  children,
}: ProfileLinkProps) {
  const className = slot ? ui.className(slot) : undefined
  const style = slot ? ui.style(slot) : undefined

  if (Link) {
    return (
      <Link to={to} className={className} style={style}>
        {children}
      </Link>
    )
  }
  return (
    <a href={to} className={className} style={style}>
      {children}
    </a>
  )
}

export interface ProfileCardProps {
  title: string
  ui: ProfileStyler
  testId?: string
  children: ReactNode
}

/** The `<section>` one block renders into: a heading and its content */
export function ProfileCard({ title, ui, testId, children }: ProfileCardProps) {
  return (
    <section
      className={ui.className("card")}
      style={ui.style("card")}
      data-testid={testId}
    >
      <div className={ui.className("cardBody")} style={ui.style("cardBody")}>
        <h2 className={ui.className("cardTitle")} style={ui.style("cardTitle")}>
          {title}
        </h2>
        {children}
      </div>
    </section>
  )
}

/**
 * How a tone is announced by default. A failure or a caution interrupts what
 * the reader is doing; a confirmation waits for a pause. Several of these
 * messages arrive with no page load behind them (a passkey that would not
 * register, a bot check that stalled), and nothing else would say so.
 */
const TONE_ROLE = {
  success: "status",
  error: "alert",
  warning: "alert",
} as const

export interface NoticeProps {
  tone: "success" | "error" | "warning"
  ui: ProfileStyler
  testId?: string
  /** Referenced by the `aria-describedby` of the input the message is about */
  id?: string
  /**
   * Override the announcement. Pass null where something inside carries it
   * instead, so that buttons and fields stay out of the live region.
   */
  role?: "alert" | "status" | null
  children: ReactNode
}

/** A confirmation, failure, or caution message within a block */
export function Notice({
  tone,
  ui,
  testId,
  id,
  role = TONE_ROLE[tone],
  children,
}: NoticeProps) {
  return (
    <div
      id={id}
      role={role ?? undefined}
      className={ui.className(tone)}
      style={ui.style(tone)}
      data-testid={testId}
    >
      {children}
    </div>
  )
}
