import { Form, redirect } from "react-router"
import { getAuthErrorMessage } from "@activescott/auth"
import { getSession } from "~/lib/auth.server"
import type { Route } from "./+types/login"

export async function loader({ request }: Route.LoaderArgs) {
  const session = await getSession(request)
  if (session) throw redirect("/dashboard")

  const url = new URL(request.url)
  const errorCode = url.searchParams.get("error")
  return {
    sent: url.searchParams.get("sent") === "1",
    error: errorCode ? getAuthErrorMessage(errorCode) : null,
  }
}

export default function Login({ loaderData }: Route.ComponentProps) {
  const { sent, error } = loaderData

  return (
    <main className="container mx-auto p-8 max-w-sm">
      <h1 className="text-2xl font-bold mb-4">Sign in</h1>

      {/* Posts directly to the auth catch-all route. The provider sends
          the email, sets the challenge cookie, and redirects back here
          with ?sent=1 — no action needed in this route. */}
      <Form
        method="post"
        action="/auth/email/initiate"
        reloadDocument
        className="flex flex-col gap-3"
      >
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
          {sent ? "Resend" : "Send magic link"}
        </button>
      </Form>

      {sent && (
        <>
          <p className="text-green-700 mt-3">
            Check your email for a sign-in link and code.
          </p>

          {/* Posts to the auth catch-all route; the provider verifies the
              code against the challenge cookie and redirects to the
              dashboard. */}
          <Form
            method="post"
            action="/auth/email/verify"
            reloadDocument
            className="flex flex-col gap-3 mt-6"
          >
            <label htmlFor="code">Or enter the code from the email</label>
            <input
              id="code"
              name="code"
              type="text"
              // one-time-code enables iOS/macOS AutoFill of the emailed code
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              className="border p-2 rounded font-mono text-2xl tracking-[0.5em] text-center"
            />
            <button
              type="submit"
              className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
            >
              Sign in with code
            </button>
          </Form>

          {/* text-amber-900 is explicit because the page inherits near-white
              text in dark mode while this box keeps a light background */}
          <aside className="mt-4 p-3 border border-amber-300 bg-amber-50 text-amber-900 text-sm rounded">
            <strong>Dev mode:</strong> this example wires up{" "}
            <code>NodemailerTransport</code> with{" "}
            <code>isDevelopment=true</code>, so no email is actually sent — the
            magic link and code are printed to the{" "}
            <strong>server console</strong> (the terminal running{" "}
            <code>npm run dev</code>). Enter the code above or paste the link
            into the browser to finish signing in.
          </aside>
        </>
      )}
      {error && <p className="text-red-700 mt-3">Error: {error}</p>}
    </main>
  )
}
