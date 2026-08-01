import { useState } from "react"
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
        Signed in as <code>{String(loaderData.user.metadata?.identifier)}</code>
      </p>
      <AddPasskey />

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

function AddPasskey() {
  const [status, setStatus] = useState<
    { state: "idle" } | { state: "added" } | { state: "error"; message: string }
  >({ state: "idle" })

  async function handleClick() {
    try {
      const { registerPasskey } = await import("~/lib/passkey.client")
      await registerPasskey()
      setStatus({ state: "added" })
    } catch (caught) {
      setStatus({
        state: "error",
        message:
          caught instanceof Error ? caught.message : "Adding a passkey failed",
      })
    }
  }

  return (
    <section className="mb-6 p-4 border rounded">
      <h2 className="font-semibold mb-2">Passkeys</h2>
      <p className="text-sm mb-3">
        Add a passkey to sign in with Touch ID, Face ID, Windows Hello, or your
        password manager — no email or text required.
      </p>
      <button
        type="button"
        onClick={handleClick}
        className="border py-2 px-4 rounded hover:bg-gray-50 dark:hover:bg-gray-800"
      >
        Add a passkey
      </button>
      {status.state === "added" && (
        <p className="text-green-700 mt-3">Passkey added.</p>
      )}
      {status.state === "error" && (
        <p className="text-red-700 mt-3" data-testid="passkey-error">
          Error: {status.message}
        </p>
      )}
    </section>
  )
}
