import type { CSSProperties } from "react"

/**
 * Per-slot class name overrides. A value here replaces the built-in styling of
 * that slot rather than adding to it, so an application can dress the blocks in
 * its own framework's classes (Bootstrap, Tailwind, ...) with no leftovers.
 */
export interface ProfileClassNames {
  /** Page wrapper, `ProfilePage` only */
  container?: string
  /** Page `<h1>`, `ProfilePage` only */
  title?: string
  /** The `<section>` around a block */
  card?: string
  /** The padded `<div>` inside a block, Bootstrap's `card-body` */
  cardBody?: string
  /** A block's `<h2>` */
  cardTitle?: string
  /** The `<h3>` over an add-a-sign-in-method form */
  subheading?: string
  /** Explanatory paragraph under a block title */
  description?: string
  definitionList?: string
  definitionTerm?: string
  definitionValue?: string
  tableWrapper?: string
  table?: string
  th?: string
  td?: string
  /** The passkey `<ul>` */
  list?: string
  listItem?: string
  /** The passkey's nickname or abbreviated credential id */
  itemName?: string
  /** The trailing detail on a list item (added, last used) */
  itemDetail?: string
  /** Wrapper around one label and input */
  field?: string
  label?: string
  input?: string
  helpText?: string
  /** Wrapper around a fixed prefix and an input, Bootstrap's `input-group` */
  inputGroup?: string
  /** The fixed prefix itself, e.g. the country calling code */
  inputGroupText?: string
  /** Row of buttons at the end of a form */
  actions?: string
  /** Opens an add-a-sign-in-method form, or adds a passkey (`btn btn-outline-primary`) */
  addButton?: string
  /** Submits a form (`btn btn-primary`) */
  submitButton?: string
  /** Abandons a form (`btn btn-outline-secondary`) */
  cancelButton?: string
  /** Confirms an account merge (`btn btn-warning`) */
  mergeButton?: string
  /** Confirmation message (`alert alert-success`) */
  success?: string
  /** Failure message (`alert alert-danger`) */
  error?: string
  /** Caution, including the merge offer (`alert alert-warning`) */
  warning?: string
  /** Where the Turnstile widget renders */
  turnstile?: string
  muted?: string
}

/** A named piece of a profile block that can be styled or class-overridden */
export type ProfileSlot = keyof ProfileClassNames

/**
 * Colors come from the CSS system palette rather than fixed values, so the
 * blocks follow the reader's light/dark preference with no media query, which
 * an inline style cannot express. `colorScheme: "light dark"` on the container
 * is what tells the browser both schemes are supported.
 */
const TEXT = "CanvasText"
const BACKGROUND = "Canvas"
const MUTED = "GrayText"
const BORDER = "ButtonBorder"

/** A tint of the text color over the background, readable in both schemes */
const TINT = "color-mix(in srgb, CanvasText 4%, Canvas)"
const BUTTON_TINT = "color-mix(in srgb, CanvasText 12%, Canvas)"

const SYSTEM_FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
const MONO_FONT = "ui-monospace, SFMono-Regular, Menlo, monospace"

const BUTTON: CSSProperties = {
  display: "inline-block",
  font: "inherit",
  color: TEXT,
  background: BACKGROUND,
  border: `1px solid ${BORDER}`,
  borderRadius: 4,
  padding: "6px 12px",
  textDecoration: "none",
  cursor: "pointer",
}

const NOTICE: CSSProperties = {
  border: `1px solid ${BORDER}`,
  borderRadius: 6,
  background: TINT,
  padding: "8px 12px",
  margin: "0 0 12px",
}

/**
 * The built-in look, one entry per slot. Applied as `style={...}` by the
 * components, so there is no stylesheet to import. Deliberately plain and
 * colorless: an application that wants its own design system supplies classes.
 */
export const PROFILE_STYLES: Record<ProfileSlot, CSSProperties> = {
  container: {
    colorScheme: "light dark",
    color: TEXT,
    background: BACKGROUND,
    fontFamily: SYSTEM_FONT,
    fontSize: 14,
    lineHeight: 1.5,
    maxWidth: 720,
    margin: "0 auto",
    padding: "24px 16px 64px",
  },
  title: { fontSize: 24, fontWeight: 600, margin: "0 0 20px" },
  card: {
    border: `1px solid ${BORDER}`,
    borderRadius: 6,
    marginBottom: 16,
  },
  cardBody: { padding: 16 },
  cardTitle: { fontSize: 16, fontWeight: 600, margin: "0 0 12px" },
  subheading: { fontSize: 14, fontWeight: 600, margin: "16px 0 8px" },
  description: { color: MUTED, margin: "0 0 12px" },
  definitionList: {
    display: "grid",
    gridTemplateColumns: "minmax(120px, max-content) 1fr",
    gap: "4px 16px",
    margin: 0,
  },
  definitionTerm: { color: MUTED },
  definitionValue: { margin: 0, wordBreak: "break-word" },
  tableWrapper: { overflowX: "auto", marginBottom: 12 },
  table: { borderCollapse: "collapse", width: "100%" },
  th: {
    textAlign: "left",
    fontWeight: 600,
    whiteSpace: "nowrap",
    padding: "8px 12px",
    borderBottom: `2px solid ${BORDER}`,
  },
  td: {
    padding: "8px 12px",
    borderBottom: `1px solid ${BORDER}`,
    verticalAlign: "top",
  },
  list: {
    listStyle: "none",
    margin: "0 0 12px",
    padding: 0,
    border: `1px solid ${BORDER}`,
    borderRadius: 6,
  },
  listItem: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "baseline",
    gap: 8,
    padding: "8px 12px",
  },
  itemName: {
    fontFamily: MONO_FONT,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  itemDetail: { color: MUTED, fontSize: 12, whiteSpace: "nowrap" },
  field: { marginBottom: 12 },
  label: { display: "block", marginBottom: 4 },
  input: {
    display: "block",
    width: "100%",
    font: "inherit",
    color: TEXT,
    background: BACKGROUND,
    border: `1px solid ${BORDER}`,
    borderRadius: 4,
    padding: "6px 8px",
  },
  helpText: { fontSize: 12, color: MUTED, marginTop: 4 },
  inputGroup: { display: "flex", alignItems: "stretch" },
  inputGroupText: {
    background: TINT,
    border: `1px solid ${BORDER}`,
    borderRight: "none",
    borderRadius: "4px 0 0 4px",
    padding: "6px 8px",
  },
  actions: { display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" },
  addButton: BUTTON,
  submitButton: { ...BUTTON, background: BUTTON_TINT },
  cancelButton: BUTTON,
  mergeButton: { ...BUTTON, background: BUTTON_TINT },
  success: NOTICE,
  // The palette has no system color for danger, so an error is set apart by a
  // heavier edge rather than by hue
  error: { ...NOTICE, borderLeft: `4px solid ${TEXT}` },
  warning: { ...NOTICE, borderLeft: `4px solid ${MUTED}` },
  turnstile: { display: "flex", justifyContent: "center", marginBottom: 12 },
  muted: { color: MUTED },
}

/** Separates passkeys in the list; the first item has the list's own edge above it */
export const LIST_ITEM_DIVIDER: CSSProperties = {
  borderTop: `1px solid ${BORDER}`,
}

/**
 * Resolves what to put on each element: the application's class when it
 * supplied one, the built-in inline style otherwise.
 *
 * They are deliberately exclusive. An inline style beats any class in
 * specificity, so emitting both would mean an application's Bootstrap or
 * Tailwind class silently lost to the built-in look.
 */
export interface ProfileStyler {
  className(slot: ProfileSlot): string | undefined
  style(slot: ProfileSlot): CSSProperties | undefined
}

export function createStyler(
  classNames: ProfileClassNames | undefined,
  includeDefaultStyles: boolean,
): ProfileStyler {
  return {
    className: (slot) => classNames?.[slot],
    style: (slot) =>
      !includeDefaultStyles || classNames?.[slot]
        ? undefined
        : PROFILE_STYLES[slot],
  }
}
