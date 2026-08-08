/**
 * The admin configuration page. Shows how auth is actually configured — the
 * session cookie, each provider's settings, abuse limits with defaults
 * resolved, and which stores are wired up.
 *
 * Secrets are removed before they reach this component: `Auth.describeConfig`
 * redacts the session secret, and each provider's `describe()` decides what of
 * its own configuration is safe to reveal.
 */
import { Link } from "react-router"
import { adminConfigLoader } from "~/lib/auth.server"
import { AdminConfigPage } from "@activescott/auth-adapter-react-router/admin"
import type { Route } from "./+types/admin.config"

export function meta() {
  return [
    { title: "Configuration · Admin" },
    { name: "robots", content: "noindex, nofollow" },
  ]
}

export function loader({ request }: Route.LoaderArgs) {
  return adminConfigLoader({ request })
}

export default function AdminConfig({ loaderData }: Route.ComponentProps) {
  return <AdminConfigPage data={loaderData} linkComponent={Link} />
}
