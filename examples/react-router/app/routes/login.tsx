import { Form, data, redirect } from "react-router"
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

  if (!result.success) {
    return {
      error: result.error ?? "Failed to send magic link.",
      message: null,
    }
  }

  // The OTP challenge cookie (from result.setCookies) must reach the
  // browser so the code the user types can be matched to this send
  const headers = new Headers()
  for (const cookie of result.setCookies ?? []) {
    headers.append("Set-Cookie", cookie)
  }
  return data(
    { message: result.message ?? "Check your email.", error: null },
    { headers },
  )
}

export default function Login({
  actionData,
  loaderData,
}: Route.ComponentProps) {
  const sent = Boolean(actionData?.message)

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
          {sent ? "Resend" : "Send magic link"}
        </button>
      </Form>
      {sent && (
        <>
          <p className="text-green-700 mt-3">{actionData?.message}</p>

          {/* Posts to the auth catch-all route; the provider verifies the
              code against the challenge cookie and redirects to the
              dashboard. reloadDocument keeps it a plain browser POST so the
              redirect + Set-Cookie behave like the magic-link click. */}
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
      {(actionData?.error || loaderData?.error) && (
        <p className="text-red-700 mt-3">
          Error: {actionData?.error || loaderData?.error}
        </p>
      )}
    </main>
  )
}
