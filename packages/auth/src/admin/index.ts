export { createAdminData, AdminNotSupportedError } from "./admin-data.js"
export type {
  AdminData,
  AdminIdentityRow,
  AdminUserRow,
  AdminUsersPage,
} from "./admin-data.js"

export {
  createAdminPredicate,
  isAdminUser,
  ADMIN_IDENTIFIERS_ENV,
} from "./admin-predicate.js"
export type { AdminPredicate } from "./admin-predicate.js"
