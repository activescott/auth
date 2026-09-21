import { logout } from "~/lib/auth.server"
import type { Route } from "./+types/logout"

// A route with no component is a resource route, and react-router runs no
// Origin check on those, so hand the request to logout and let it run one.
export function action({ request }: Route.ActionArgs) {
  return logout(request, "/")
}

export function loader() {
  return logout("/")
}
