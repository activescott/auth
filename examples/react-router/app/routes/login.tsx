import { Form, redirect } from "react-router"
import {
  usePasskeySignIn,
  usePreservedInput,
  useTurnstile,
} from "@activescott/auth-adapter-react-router/client"
import { getSession, signInLoader } from "~/lib/auth.server"
import { passkeys } from "~/lib/passkey.client"
import {
  AntiBotFields,
  AntiBotSubmitButton,
} from "~/components/anti-bot-fields"
import { CodeForm } from "~/components/code-form"
import { TabLink } from "~/components/tab-link"
import type { Route } from "./+types/login"

export async function loader({ request }: Route.LoaderArgs) {
  const session = await getSession(request)
  if (session) throw redirect("/dashboard")

  // Everything the page renders from: which provider's form to show (?via=,
  // which survives the round trip because the provider redirects back to the
  // page the form was posted from: /login?via=sms → initiate →
  // /login?via=sms&sent=1), whether a message went out (?sent=1), the error
  // message for ?error=, and the anti-bot form token, minted per render
  // because the abuse checks compare it against submit time.
  return signInLoader(request)
}

export default function Login({ loaderData }: Route.ComponentProps) {
  const { via, sent, error, formToken, turnstileSiteKey } = loaderData
  const formProps = { sent, formToken, turnstileSiteKey }

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

      {via === "sms" ? (
        <SmsLogin {...formProps} />
      ) : (
        <EmailLogin {...formProps} />
      )}

      {error && <p className="text-red-700 mt-3">Error: {error}</p>}

      <PasskeyLogin />

      <p className="text-xs text-gray-400 mt-8">
        Dev note: this example keeps users, identities, and passkey credentials
        in memory, so restarting the server forgets them all. A passkey saved in
        your password manager survives the restart, but the server no longer
        recognizes it (&ldquo;Unknown credential&rdquo;) — delete it there and
        add a new one. A real app would back the stores with a database.
      </p>
    </main>
  )
}

interface LoginFormProps {
  sent: boolean
  formToken: string
  turnstileSiteKey: string | null
}

/** Start a conditional (autofill) passkey request when the login page loads */
const OFFER_PASSKEY_AUTOFILL = false

function PasskeyLogin() {
  // autofill offers passkeys in the browser's autofill on the email input
  // (autoComplete="username webauthn"); clicking the button aborts that
  // pending request and runs the modal flow instead. Off here for the reason
  // on the hook's option: password manager extensions commonly answer the
  // pending request with their own dialog the moment the page loads. Turn it
  // on if your users' browsers handle it natively.
  //
  // On success the hook does a full page load of redirectTo, so the
  // dashboard renders on the server with the new session.
  const passkey = usePasskeySignIn({
    client: passkeys,
    redirectTo: "/dashboard",
    autofill: OFFER_PASSKEY_AUTOFILL,
  })

  return (
    <div className="mt-6 pt-4 border-t">
      <button
        type="button"
        onClick={passkey.signIn}
        disabled={passkey.pending}
        className="w-full border py-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800"
      >
        Sign in with a passkey
      </button>
      <p className="text-sm text-gray-500 mt-2">
        Already added a passkey to your account? Sign in with it here. First
        time? Sign in with your email or mobile number above, then add a passkey
        from the dashboard.
      </p>
      {passkey.error && (
        <p className="text-red-700 mt-3" data-testid="passkey-error">
          Error: {passkey.error}
        </p>
      )}
    </div>
  )
}

function EmailLogin({ sent, formToken, turnstileSiteKey }: LoginFormProps) {
  // The page reloads on the way back from the provider; this brings the
  // address back so the user can resend without retyping it
  const [email, setEmail, saveEmail] = usePreservedInput("login.email")
  const turnstile = useTurnstile(turnstileSiteKey)

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
        <AntiBotFields formToken={formToken} turnstile={turnstile} />
        <label htmlFor="email">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          pattern=".+@.+\..+"
          title="Enter a full email address, e.g. name@example.com"
          // "webauthn" lets the browser offer passkeys in the autofill
          // dropdown on this field (conditional UI)
          autoComplete="username webauthn"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          className="border p-2 rounded"
        />
        <AntiBotSubmitButton turnstile={turnstile}>
          {sent ? "Resend" : "Send magic link"}
        </AntiBotSubmitButton>
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

function SmsLogin({ sent, formToken, turnstileSiteKey }: LoginFormProps) {
  // The visible input takes the national number; the hidden field submits
  // the full E.164 value the provider expects. This example is wired for
  // US/Canada numbers (fixed +1) — adapt the prefix for your market.
  const [nationalNumber, setNationalNumber, savePhone] =
    usePreservedInput("login.phone")
  const turnstile = useTurnstile(turnstileSiteKey)

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
        <AntiBotFields formToken={formToken} turnstile={turnstile} />
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
        <AntiBotSubmitButton turnstile={turnstile}>
          {sent ? "Resend code" : "Text me a code"}
        </AntiBotSubmitButton>
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
