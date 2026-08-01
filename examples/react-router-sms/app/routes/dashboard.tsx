import { Form } from "react-router"
import { requireAuth } from "~/lib/auth.server"
import type { Route } from "./+types/dashboard"

export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request)
  return { user }
}

export default function Dashboard({ loaderData }: Route.ComponentProps) {
  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      <p className="mb-4">
        Signed in as <code>{String(loaderData.user.metadata?.phone)}</code>
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
