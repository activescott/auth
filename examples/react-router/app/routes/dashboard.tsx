import { useState } from "react"
import { Form, useRevalidator } from "react-router"
import { requireAuth, listPasskeys } from "~/lib/auth.server"
import type { Route } from "./+types/dashboard"

export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request)
  return { user, passkeys: await listPasskeys(user.id) }
}

export default function Dashboard({ loaderData }: Route.ComponentProps) {
  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      <p className="mb-4">
        Signed in as <code>{String(loaderData.user.metadata?.identifier)}</code>
      </p>
      <Passkeys passkeys={loaderData.passkeys} />

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

function Passkeys({
  passkeys,
}: {
  passkeys: Route.ComponentProps["loaderData"]["passkeys"]
}) {
  const [status, setStatus] = useState<
    { state: "idle" } | { state: "added" } | { state: "error"; message: string }
  >({ state: "idle" })
  const revalidator = useRevalidator()

  async function handleClick() {
    try {
      const { registerPasskey } = await import("~/lib/passkey.client")
      await registerPasskey()
      setStatus({ state: "added" })
      // Reload the loader data so the new passkey shows in the list
      await revalidator.revalidate()
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
        Sign in with Touch ID, Face ID, Windows Hello, or your password manager
        — no email or text required.
      </p>

      {passkeys.length > 0 && (
        <ul className="mb-3 divide-y border rounded">
          {passkeys.map((passkey) => (
            <li
              key={passkey.credentialId}
              data-testid="passkey-item"
              className="p-2 text-sm flex items-baseline justify-between gap-2"
            >
              <span className="font-mono truncate" title={passkey.credentialId}>
                {passkey.nickname ??
                  abbreviateCredentialId(passkey.credentialId)}
              </span>
              <span className="text-gray-500 whitespace-nowrap">
                {passkey.synced ? "synced" : "device-bound"} · added{" "}
                {formatDate(passkey.createdAt)}
                {passkey.lastUsedAt &&
                  ` · last used ${formatDate(passkey.lastUsedAt)}`}
              </span>
            </li>
          ))}
        </ul>
      )}

      <button
        type="button"
        onClick={handleClick}
        className="border py-2 px-4 rounded hover:bg-gray-50 dark:hover:bg-gray-800"
      >
        {passkeys.length > 0 ? "Add another passkey" : "Add a passkey"}
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

function abbreviateCredentialId(credentialId: string): string {
  const PREFIX_LENGTH = 8
  return `Passkey ${credentialId.slice(0, PREFIX_LENGTH)}…`
}

function formatDate(isoDate: string): string {
  return new Date(isoDate).toLocaleDateString()
}
