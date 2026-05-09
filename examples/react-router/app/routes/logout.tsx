import { logout } from "~/lib/auth.server"

export function action() {
  return logout("/")
}

export function loader() {
  return logout("/")
}
