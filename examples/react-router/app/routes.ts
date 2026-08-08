import { type RouteConfig, index, route } from "@react-router/dev/routes"

export default [
  index("routes/home.tsx"),
  route("login", "routes/login.tsx"),
  route("logout", "routes/logout.tsx"),
  route("dashboard", "routes/dashboard.tsx"),
  route("auth/:provider/:action", "routes/auth.$provider.$action.tsx"),
  // The admin dashboard the library ships. Two routes, both a loader and a
  // one-line component; everything else comes from the adapter.
  route("admin/users", "routes/admin.users.tsx"),
  route("admin/config", "routes/admin.config.tsx"),
  route("e2e/otp-code", "routes/e2e.otp-code.tsx"),
] satisfies RouteConfig
