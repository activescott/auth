import type { ProfileClassNames } from "./profile-styles.js"

/**
 * Bootstrap 5 classes for every profile slot, so an application on Bootstrap
 * gets a finished page from one prop instead of naming 34 slots itself.
 *
 * Typed `Required<ProfileClassNames>`, which is what keeps it complete: a slot
 * added to the interface fails this file's build until it has a class here.
 *
 * Spread it to change a slot and keep the rest:
 *
 * @example
 * ```tsx
 * <ProfilePage
 *   {...loaderData}
 *   classNames={{
 *     ...BOOTSTRAP_PROFILE_CLASS_NAMES,
 *     title: "fw-bold text-primary mb-4",
 *   }}
 * />
 * ```
 */
export const BOOTSTRAP_PROFILE_CLASS_NAMES: Required<ProfileClassNames> = {
  container: "container py-5",
  title: "mb-4",
  card: "card mb-4",
  cardBody: "card-body",
  cardTitle: "card-title h5",
  subheading: "h6",
  description: "text-muted",
  definitionList: "row mb-0",
  definitionTerm: "col-sm-4",
  definitionValue: "col-sm-8",
  tableWrapper: "table-responsive mb-3",
  table: "table",
  // `.table` reaches the cells by descendant selector, so they need no class of
  // their own; the empty string is still what drops the built-in padding and
  // borders, which would otherwise outrank it
  th: "",
  td: "",
  list: "list-group mb-3",
  listItem:
    "list-group-item d-flex justify-content-between align-items-baseline gap-2",
  itemName: "font-monospace text-truncate",
  itemDetail: "text-muted text-nowrap",
  field: "mb-3",
  label: "form-label",
  input: "form-control",
  helpText: "form-text",
  inputGroup: "input-group",
  inputGroupText: "input-group-text",
  actions: "d-flex gap-2",
  addButton: "btn btn-outline-primary",
  submitButton: "btn btn-primary",
  cancelButton: "btn btn-outline-secondary",
  mergeButton: "btn btn-warning",
  success: "alert alert-success",
  error: "alert alert-danger",
  warning: "alert alert-warning",
  turnstile: "d-flex justify-content-center mb-3",
  muted: "text-muted",
}
