import { Link } from "react-router"
import { optionalAuth } from "~/lib/auth.server"
import type { Route } from "./+types/home"

export function meta() {
  return [{ title: "RR Auth Example" }]
}

export async function loader({ request }: Route.LoaderArgs) {
  const user = await optionalAuth(request)
  return { user }
}

export default function Home({ loaderData }: Route.ComponentProps) {
  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">RR Auth Example</h1>
      <p className="mb-6">
        Minimal React Router v7 app demonstrating <code>@activescott/auth</code>{" "}
        with email magic-link login.
      </p>
      {loaderData.user ? (
        <p>
          Signed in as <code>{String(loaderData.user.metadata?.email)}</code>.{" "}
          <Link to="/dashboard" className="underline">
            Go to dashboard
          </Link>
          .
        </p>
      ) : (
        <Link to="/login" className="underline">
          Sign in
        </Link>
      )}
    </main>
  )
}
