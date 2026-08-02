import { useEffect, useState } from "react"
import { Form, redirect } from "react-router"
import { getAuthErrorMessage } from "@activescott/auth"
import { getSession } from "~/lib/auth.server"
import { CodeForm } from "~/components/code-form"
import { TabLink } from "~/components/tab-link"
import { usePreservedInput } from "~/hooks/use-preserved-input"
import type { Route } from "./+types/login"

export async function loader({ request }: Route.LoaderArgs) {
  const session = await getSession(request)
  if (session) throw redirect("/dashboard")

  const url = new URL(request.url)
  const errorCode = url.searchParams.get("error")
  return {
    // Which provider's form to show. The provider redirects back to the
    // page the form was posted from (via Referer), so ?via=sms survives
    // the round trip: /login?via=sms → initiate → /login?via=sms&sent=1.
    via: url.searchParams.get("via") === "sms" ? "sms" : "email",
    sent: url.searchParams.get("sent") === "1",
    error: errorCode ? getAuthErrorMessage(errorCode) : null,
  }
}

export default function Login({ loaderData }: Route.ComponentProps) {
  const { via, sent, error } = loaderData

  return (
    <main className="container mx-auto p-8 max-w-sm">
      <h1 className="text-2xl font-bold mb-4">Sign in</h1>

      <nav className="flex gap-4 mb-6 border-b">
        <TabLink to="/login" active={via === "email"}>
          Email
        </TabLink>
        <TabLink to="/login?via=sms" active={via === "sms"}>
          Phone
        </TabLink>
      </nav>

      {via === "email" ? <EmailLogin sent={sent} /> : <SmsLogin sent={sent} />}

      {error && <p className="text-red-700 mt-3">Error: {error}</p>}

      <PasskeyLogin />
    </main>
  )
}

function PasskeyLogin() {
  const [error, setError] = useState<string | null>(null)

  // Conditional UI: offer passkeys in the browser's autofill on the
  // email input (autoComplete="username webauthn"). The request stays
  // pending until the user picks a passkey there; clicking the passkey
  // button below aborts it and runs the modal flow instead.
  useEffect(() => {
    let cancelled = false
    async function offerPasskeyAutofill() {
      const { signInWithPasskey, isConditionalUIAvailable } =
        await import("~/lib/passkey.client")
      if (!(await isConditionalUIAvailable())) return
      try {
        await signInWithPasskey(true)
        // Full page load (not a client-side navigation) so password
        // managers see the sign-in land — 1Password otherwise reports
        // a problem after a successful assertion.
        if (!cancelled) window.location.assign("/dashboard")
      } catch {
        // Aborted by the modal flow or dismissed — not an error to show
      }
    }
    void offerPasskeyAutofill()
    return () => {
      cancelled = true
    }
  }, [])

  async function handleClick() {
    setError(null)
    try {
      const { signInWithPasskey } = await import("~/lib/passkey.client")
      await signInWithPasskey()
      // Full page load — see the conditional-UI comment above
      window.location.assign("/dashboard")
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "Passkey sign-in failed",
      )
    }
  }

  return (
    <div className="mt-6 pt-4 border-t">
      <button
        type="button"
        onClick={handleClick}
        className="w-full border py-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800"
      >
        Sign in with a passkey
      </button>
      <p className="text-sm text-gray-500 mt-2">
        Already added a passkey to your account? Sign in with it here. First
        time? Sign in with your email or mobile number above, then add a passkey
        from the dashboard.
      </p>
      {error && (
        <p className="text-red-700 mt-3" data-testid="passkey-error">
          Error: {error}
        </p>
      )}
    </div>
  )
}

function EmailLogin({ sent }: { sent: boolean }) {
  const [email, setEmail, saveEmail] = usePreservedInput("login.email")

  return (
    <>
      {/* Posts directly to the auth catch-all route. The provider sends
          the email, sets the challenge cookie, and redirects back here
          with ?sent=1 — no action needed in this route. */}
      <Form
        method="post"
        action="/auth/email/initiate"
        reloadDocument
        className="flex flex-col gap-3"
        onSubmit={saveEmail}
      >
        <label htmlFor="email">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          // "webauthn" lets the browser offer passkeys in the autofill
          // dropdown on this field (conditional UI)
          autoComplete="username webauthn"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
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

          <CodeForm action="/auth/email/verify">
            Or enter the code from the email
          </CodeForm>

          {/* text-amber-900 is explicit because the page inherits near-white
              text in dark mode while this box keeps a light background */}
          <aside className="mt-4 p-3 border border-amber-300 bg-amber-50 text-amber-900 text-sm rounded">
            <strong>Dev mode:</strong> unless SMTP is configured in{" "}
            <code>.env</code>, no email is actually sent — the magic link and
            code are printed to the <strong>server console</strong> (the
            terminal running <code>npm run dev</code>). Enter the code above or
            paste the link into the browser to finish signing in.
          </aside>
        </>
      )}
    </>
  )
}

function SmsLogin({ sent }: { sent: boolean }) {
  // The visible input takes the national number; the hidden field submits
  // the full E.164 value the provider expects. This example is wired for
  // US/Canada numbers (fixed +1) — adapt the prefix for your market.
  const [nationalNumber, setNationalNumber, savePhone] =
    usePreservedInput("login.phone")

  return (
    <>
      {/* Posts directly to the auth catch-all route. The provider texts
          the code, sets the challenge cookie, and redirects back here
          with ?sent=1 — no action needed in this route. */}
      <Form
        method="post"
        action="/auth/sms/initiate"
        reloadDocument
        className="flex flex-col gap-3"
        onSubmit={savePhone}
      >
        <label htmlFor="phone">Mobile phone number</label>
        <div className="flex rounded border focus-within:ring-2 focus-within:ring-blue-600">
          <span className="flex items-center px-3 bg-gray-100 text-gray-600 border-r rounded-l select-none">
            +1
          </span>
          <input
            id="phone"
            type="tel"
            autoComplete="tel-national"
            inputMode="tel"
            placeholder="415 555 0100"
            required
            value={nationalNumber}
            onChange={(event) => setNationalNumber(event.target.value)}
            className="p-2 rounded-r flex-1 min-w-0 outline-none"
          />
        </div>
        <input type="hidden" name="phone" value={`+1${nationalNumber}`} />
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

          <CodeForm action="/auth/sms/verify">
            Enter the code from the text
          </CodeForm>

          {/* text-amber-900 is explicit because the page inherits near-white
              text in dark mode while this box keeps a light background */}
          <aside className="mt-4 p-3 border border-amber-300 bg-amber-50 text-amber-900 text-sm rounded">
            <strong>Dev mode:</strong> unless Twilio is configured in{" "}
            <code>.env</code>, no SMS is actually sent — the code is printed to
            the <strong>server console</strong> (the terminal running{" "}
            <code>npm run dev</code>). Set the <code>TWILIO_*</code> vars in{" "}
            <code>.env</code> to text real messages.
          </aside>
        </>
      )}
    </>
  )
}
