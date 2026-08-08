export { createAdminHandlers } from "./admin-handlers.js"
export type {
  AdminHandlers,
  AdminUsersLoaderData,
  AdminConfigLoaderData,
} from "./admin-handlers.js"

export type {
  AdminOptions,
  AdminPredicate,
  AdminForbiddenBehavior,
  AdminMetadataColumn,
  AdminShowColumns,
  AdminClassNames,
} from "./admin-options.js"
export {
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  DEFAULT_BASE_PATH,
} from "./admin-options.js"

export { ADMIN_IDENTIFIERS_ENV } from "./require-admin.js"

export {
  AdminUsersPage,
  SORT_CREATED_AT,
  SORT_LAST_LOGIN_AT,
} from "./admin-users-page.js"
export type { AdminUsersPageProps } from "./admin-users-page.js"

export { AdminConfigPage } from "./admin-config-page.js"
export type { AdminConfigPageProps } from "./admin-config-page.js"

export { AdminLayout } from "./admin-layout.js"
export type {
  AdminLayoutProps,
  AdminLinkComponent,
  AdminPresentationProps,
} from "./admin-layout.js"

export {
  ADMIN_STYLES,
  STRIPED_ROW_STYLE,
  IDENTITY_STYLE,
  createStyler,
} from "./admin-styles.js"
export type { AdminSlot, AdminStyler } from "./admin-styles.js"
