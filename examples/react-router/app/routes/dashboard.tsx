import { Form, redirect } from "react-router"
import { getSession } from "~/lib/auth.server"
import type { Route } from "./+types/dashboard"

export async function loader({ request }: Route.LoaderArgs) {
  const session = await getSession(request)
  if (!session) throw redirect("/login")
  return { user: session.user, provider: session.identity.provider }
}

export default function Dashboard({ loaderData }: Route.ComponentProps) {
  const { user, provider } = loaderData
  const email = user.metadata?.email as string | null | undefined
  const name = user.metadata?.name as string | null | undefined
  const displayName = email ?? name ?? "—"

  const providerLabel: Record<string, string> = {
    email: "email magic link",
    google: "Google",
    github: "GitHub",
  }

  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      <p className="mb-1">
        Signed in as <code>{displayName}</code>
      </p>
      <p className="mb-4 text-sm text-gray-500">
        via {providerLabel[provider] ?? provider}
      </p>
      <Form method="post" action="/logout">
        <button
          type="submit"
          className="bg-gray-800 text-white py-2 px-4 rounded hover:bg-gray-900"
        >
          Log out
        </button>
      </Form>
    </main>
  )
}
