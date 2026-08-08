import type { CSSProperties } from "react"
import type { AdminClassNames } from "./admin-options.js"

/** A named piece of an admin page that can be styled or class-overridden */
export type AdminSlot = keyof AdminClassNames

/**
 * Colors come from the CSS system palette rather than fixed hex values, so the
 * pages follow the reader's light/dark preference with no media query — which
 * an inline style cannot express. `colorScheme: "light dark"` on the container
 * is what tells the browser both schemes are supported; the keywords below
 * then resolve to the active one.
 */
const TEXT = "CanvasText"
const BACKGROUND = "Canvas"
const MUTED = "GrayText"
const LINK = "LinkText"
const BORDER = "ButtonBorder"

/** A tint of the text color over the background — a stripe that works in both schemes */
const STRIPE = "color-mix(in srgb, CanvasText 4%, Canvas)"

const SYSTEM_FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
const MONO_FONT = "ui-monospace, SFMono-Regular, Menlo, monospace"

/**
 * The built-in look, one entry per slot. Applied as `style={...}` by the page
 * components — there is no stylesheet to import and nothing for a consuming
 * app to wire up.
 */
export const ADMIN_STYLES: Record<AdminSlot, CSSProperties> = {
  container: {
    colorScheme: "light dark",
    color: TEXT,
    background: BACKGROUND,
    fontFamily: SYSTEM_FONT,
    fontSize: 14,
    lineHeight: 1.5,
    maxWidth: 1400,
    margin: "0 auto",
    padding: "24px 16px 64px",
  },
  header: {
    display: "flex",
    flexWrap: "wrap",
    alignItems: "baseline",
    gap: "8px 24px",
    borderBottom: `1px solid ${BORDER}`,
    paddingBottom: 12,
    marginBottom: 20,
  },
  title: { fontSize: 20, fontWeight: 600, margin: 0 },
  nav: { display: "flex", gap: 16, marginLeft: "auto" },
  navLink: { color: LINK },
  tableWrapper: { overflowX: "auto" },
  table: { borderCollapse: "collapse", width: "100%" },
  th: {
    textAlign: "left",
    fontWeight: 600,
    whiteSpace: "nowrap",
    padding: "8px 12px",
    borderBottom: `2px solid ${BORDER}`,
    verticalAlign: "bottom",
  },
  td: {
    padding: "8px 12px",
    borderBottom: `1px solid ${BORDER}`,
    verticalAlign: "top",
  },
  // Headers read as headers, not links; the underline would be noise on every
  // sortable column.
  sortLink: { color: "inherit", textDecoration: "none" },
  badge: {
    display: "inline-block",
    border: `1px solid ${BORDER}`,
    borderRadius: 999,
    padding: "0 8px",
    fontSize: 12,
    whiteSpace: "nowrap",
  },
  code: { fontFamily: MONO_FONT, fontSize: 12, wordBreak: "break-all" },
  muted: { color: MUTED },
  empty: {
    border: `1px solid ${BORDER}`,
    borderRadius: 6,
    padding: 24,
    textAlign: "center",
    color: MUTED,
  },
  pagination: {
    display: "flex",
    alignItems: "center",
    gap: 16,
    marginTop: 16,
  },
  paginationLink: { color: LINK },
  card: {
    border: `1px solid ${BORDER}`,
    borderRadius: 6,
    padding: 16,
    marginBottom: 16,
  },
  cardTitle: { fontSize: 15, fontWeight: 600, margin: "0 0 12px" },
  definitionList: {
    display: "grid",
    gridTemplateColumns: "minmax(140px, max-content) 1fr",
    gap: "4px 16px",
    margin: 0,
  },
  definitionTerm: { color: MUTED },
  definitionValue: { margin: 0, wordBreak: "break-word" },
}

/** Background for every other table row, so long rows stay easy to track */
export const STRIPED_ROW_STYLE: CSSProperties = { background: STRIPE }

/** One identity within the identities cell */
export const IDENTITY_STYLE: CSSProperties = { marginBottom: 4 }

/**
 * Resolves what to put on each element: the application's class when it
 * supplied one, the built-in inline style otherwise.
 *
 * They are deliberately exclusive. An inline style beats any class in
 * specificity, so emitting both would mean an application's Bootstrap or
 * Tailwind class silently lost to the built-in look.
 */
export interface AdminStyler {
  className(slot: AdminSlot): string | undefined
  style(slot: AdminSlot): CSSProperties | undefined
}

export function createStyler(
  classNames: AdminClassNames | undefined,
  includeDefaultStyles: boolean,
): AdminStyler {
  return {
    className: (slot) => classNames?.[slot],
    style: (slot) =>
      !includeDefaultStyles || classNames?.[slot]
        ? undefined
        : ADMIN_STYLES[slot],
  }
}
