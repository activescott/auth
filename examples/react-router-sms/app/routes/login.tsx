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

      {/* Posts directly to the auth catch-all route. The provider texts
          the code, sets the challenge cookie, and redirects back here
          with ?sent=1 — no action needed in this route. */}
      <Form
        method="post"
        action="/auth/sms/initiate"
        reloadDocument
        className="flex flex-col gap-3"
      >
        <label htmlFor="phone">Mobile phone number</label>
        <input
          id="phone"
          name="phone"
          type="tel"
          autoComplete="tel"
          placeholder="+1 415 555 0100"
          required
          className="border p-2 rounded"
        />
        <button
          type="submit"
          className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
        >
          {sent ? "Resend code" : "Text me a code"}
        </button>
      </Form>

      {sent && (
        <>
          <p className="text-green-700 mt-3">We texted you a sign-in code.</p>

          {/* Posts to the auth catch-all route; the provider verifies the
              code against the challenge cookie and redirects to the
              dashboard. */}
          <Form
            method="post"
            action="/auth/sms/verify"
            reloadDocument
            className="flex flex-col gap-3 mt-6"
          >
            <label htmlFor="code">Enter the code from the text</label>
            <input
              id="code"
              name="code"
              type="text"
              // one-time-code enables iOS/Android autofill of the texted code
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
            <strong>Dev mode:</strong> with the default{" "}
            <code>SMS_TRANSPORT=console</code>, no SMS is actually sent — the
            code is printed to the <strong>server console</strong> (the terminal
            running <code>npm run dev</code>). Set{" "}
            <code>SMS_TRANSPORT=twilio</code> or <code>aws</code> in{" "}
            <code>.env</code> to text real messages.
          </aside>
        </>
      )}
      {error && <p className="text-red-700 mt-3">Error: {error}</p>}
    </main>
  )
}
