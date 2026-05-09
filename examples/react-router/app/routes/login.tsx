import { Form, redirect } from "react-router"
import { getAuthErrorMessage } from "@activescott/auth"
import { getSession, sendMagicLink } from "~/lib/auth.server"
import type { Route } from "./+types/login"

export async function loader({ request }: Route.LoaderArgs) {
  const session = await getSession(request)
  if (session) throw redirect("/dashboard")

  const errorCode = new URL(request.url).searchParams.get("error")
  return { error: errorCode ? getAuthErrorMessage(errorCode) : null }
}

export async function action({ request }: Route.ActionArgs) {
  const formData = await request.formData()
  const email = formData.get("email")
  if (typeof email !== "string") {
    return { error: "Email is required", message: null }
  }

  const baseUrl = new URL(request.url).origin
  const result = await sendMagicLink(email, baseUrl)

  return result.success
    ? { message: result.message ?? "Check your email.", error: null }
    : { error: result.error ?? "Failed to send magic link.", message: null }
}

export default function Login({
  actionData,
  loaderData,
}: Route.ComponentProps) {
  return (
    <main className="container mx-auto p-8 max-w-sm">
      <h1 className="text-2xl font-bold mb-4">Sign in</h1>
      <Form method="post" className="flex flex-col gap-3">
        <label htmlFor="email">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="email"
          required
          className="border p-2 rounded"
        />
        <button
          type="submit"
          className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
        >
          Send magic link
        </button>
      </Form>
      {actionData?.message && (
        <>
          <p className="text-green-700 mt-3">{actionData.message}</p>
          <aside className="mt-4 p-3 border border-amber-300 bg-amber-50 text-sm rounded">
            <strong>Dev mode:</strong> this example wires up{" "}
            <code>NodemailerTransport</code> with{" "}
            <code>isDevelopment=true</code>, so no email is actually sent — the
            magic link is printed to the <strong>server console</strong> (the
            terminal running <code>npm run dev</code>). Copy it from there and
            paste it into the browser to finish signing in.
          </aside>
        </>
      )}
      {(actionData?.error || loaderData?.error) && (
        <p className="text-red-700 mt-3">
          Error: {actionData?.error || loaderData?.error}
        </p>
      )}
    </main>
  )
}
