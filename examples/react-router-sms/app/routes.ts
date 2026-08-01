import { type RouteConfig, index, route } from "@react-router/dev/routes"

export default [
  index("routes/home.tsx"),
  route("login", "routes/login.tsx"),
  route("logout", "routes/logout.tsx"),
  route("dashboard", "routes/dashboard.tsx"),
  route("auth/:provider/:action", "routes/auth.$provider.$action.tsx"),
  route("e2e/otp-code", "routes/e2e.otp-code.tsx"),
] satisfies RouteConfig
