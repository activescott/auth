import { useState } from "react"
import { Form, Link, useRevalidator } from "react-router"
import { getAuthErrorMessage } from "@activescott/auth"
import {
  requireAuth,
  listPasskeys,
  listSignInMethods,
  createLoginFormFields,
} from "~/lib/auth.server"
import { AntiBotFields } from "~/components/anti-bot-fields"
import { CodeForm } from "~/components/code-form"
import type { Route } from "./+types/dashboard"

export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request)
  const url = new URL(request.url)
  const errorCode = url.searchParams.get("error")
  const linkParameter = url.searchParams.get("link")
  const link: "email" | "sms" | null =
    linkParameter === "sms" || linkParameter === "email" ? linkParameter : null
  return {
    user,
    passkeys: await listPasskeys(user.id),
    signInMethods: await listSignInMethods(user.id),
    // Link initiates post to the same abuse-guarded endpoints as sign-in,
    // so the forms below need the same anti-bot fields the login page uses
    antiBot: await createLoginFormFields(),
    // Which add-method form is open. The provider redirects back via
    // Referer, so ?link=email survives the initiate round trip the same way
    // ?via= does on the login page.
    link,
    sent: url.searchParams.get("sent") === "1",
    merged: url.searchParams.get("merged") === "1",
    linked: url.searchParams.get("linked") === "1" && !errorCode,
    // IDENTITY_CONFLICT is not a dead end: it means the identifier belongs
    // to another account and a merge ticket cookie is waiting, so the page
    // shows a merge prompt instead of an error message.
    conflict: errorCode === "IDENTITY_CONFLICT",
    error:
      errorCode && errorCode !== "IDENTITY_CONFLICT"
        ? getAuthErrorMessage(errorCode)
        : null,
  }
}

export default function Dashboard({ loaderData }: Route.ComponentProps) {
  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      <p className="mb-4">
        Signed in as <code>{String(loaderData.user.metadata?.identifier)}</code>
      </p>
      <SignInMethods {...loaderData} />
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

/**
 * The user's email/phone sign-in methods, with flows to add another one.
 * Adding posts to the provider's normal initiate/verify endpoints with
 * `mode=link`, which attaches the verified identifier to the signed-in user
 * instead of signing in as it. When the identifier already belongs to a
 * different account the verify comes back with error=IDENTITY_CONFLICT and
 * a merge-ticket cookie; the prompt below redeems it at
 * /auth/{provider}/link-merge to merge that account into this one.
 */
function SignInMethods({
  signInMethods,
  antiBot,
  link,
  sent,
  merged,
  linked,
  conflict,
  error,
}: Route.ComponentProps["loaderData"]) {
  return (
    <section className="mb-6 p-4 border rounded">
      <h2 className="font-semibold mb-2">Sign-in methods</h2>

      <ul className="mb-3 divide-y border rounded">
        {signInMethods.map((method) => (
          <li
            key={`${method.provider}:${method.identifier}`}
            data-testid="sign-in-method"
            className="p-2 text-sm flex items-baseline justify-between gap-2"
          >
            <span className="font-mono truncate">{method.identifier}</span>
            <span className="text-gray-500 whitespace-nowrap">
              {method.provider} · added {formatDate(method.createdAt)}
            </span>
          </li>
        ))}
      </ul>

      {merged && (
        <p className="text-green-700 mb-3" data-testid="merge-success">
          Accounts merged. All sign-in methods now open this account.
        </p>
      )}
      {linked && (
        <p className="text-green-700 mb-3" data-testid="link-success">
          Sign-in method added.
        </p>
      )}

      {link === null && (
        <nav className="flex gap-4">
          <Link className="text-blue-600 underline" to="/dashboard?link=email">
            Add an email
          </Link>
          <Link className="text-blue-600 underline" to="/dashboard?link=sms">
            Add a phone number
          </Link>
        </nav>
      )}

      {link === "email" && <AddEmail sent={sent} antiBot={antiBot} />}
      {link === "sms" && <AddPhone sent={sent} antiBot={antiBot} />}

      {conflict && link && <MergePrompt provider={link} />}
      {error && (
        <p className="text-red-700 mt-3" data-testid="link-error">
          Error: {error}
        </p>
      )}
    </section>
  )
}

type AddMethodProps = {
  sent: boolean
  antiBot: { formToken: string; turnstileSiteKey: string | null }
}

/**
 * Where the verify step should land: back on this page with ?linked=1 (and
 * the open form's ?link= so a conflict prompt knows which provider minted
 * the merge ticket). Passed as ?redirectTo= on the verify URL — the same
 * mechanism a post-login redirect uses.
 */
function verifyAction(provider: "email" | "sms"): string {
  const redirectTo = `/dashboard?link=${provider}&linked=1`
  return `/auth/${provider}/verify?redirectTo=${encodeURIComponent(redirectTo)}`
}

function AddEmail({ sent, antiBot }: AddMethodProps) {
  return (
    <div className="mt-2">
      <Form
        method="post"
        action="/auth/email/initiate"
        reloadDocument
        className="flex flex-col gap-3"
      >
        <AntiBotFields {...antiBot} />
        {/* mode=link is what makes this attach to the signed-in account
            instead of starting a new sign-in */}
        <input type="hidden" name="mode" value="link" />
        <input
          type="hidden"
          name="redirectTo"
          value="/dashboard?link=email&linked=1"
        />
        <label htmlFor="link-email">Email to add</label>
        <input
          id="link-email"
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
          {sent ? "Resend" : "Send confirmation"}
        </button>
      </Form>

      {sent && (
        <>
          <p className="text-green-700 mt-3">
            Check that inbox for a confirmation link and code.
          </p>
          <CodeForm action={verifyAction("email")} submitLabel="Add email">
            Or enter the code from the email
          </CodeForm>
        </>
      )}
    </div>
  )
}

function AddPhone({ sent, antiBot }: AddMethodProps) {
  const [nationalNumber, setNationalNumber] = useState("")

  return (
    <div className="mt-2">
      <Form
        method="post"
        action="/auth/sms/initiate"
        reloadDocument
        className="flex flex-col gap-3"
      >
        <AntiBotFields {...antiBot} />
        <input type="hidden" name="mode" value="link" />
        <label htmlFor="link-phone">Mobile phone number to add</label>
        <div className="flex rounded border focus-within:ring-2 focus-within:ring-blue-600">
          <span className="flex items-center px-3 bg-gray-100 text-gray-600 border-r rounded-l select-none">
            +1
          </span>
          <input
            id="link-phone"
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
          <p className="text-green-700 mt-3">We texted a confirmation code.</p>
          <CodeForm action={verifyAction("sms")} submitLabel="Add phone number">
            Enter the code from the text
          </CodeForm>
        </>
      )}
    </div>
  )
}

/**
 * Offered when a link attempt hit IDENTITY_CONFLICT. The merge-ticket
 * cookie set by that response authorizes exactly one merge of the other
 * account into this one; the ticket expires after a few minutes, and the
 * server re-checks this session before merging.
 */
function MergePrompt({ provider }: { provider: "email" | "sms" }) {
  return (
    <aside
      className="mt-4 p-3 border border-amber-300 bg-amber-50 text-amber-900 text-sm rounded"
      data-testid="merge-prompt"
    >
      <p className="mb-2">
        That {provider === "email" ? "email" : "phone number"} already signs in
        to a <strong>different account</strong>. You just proved it&rsquo;s
        yours, so you can merge that account into this one — all of its sign-in
        methods will open this account afterwards.
      </p>
      <Form
        method="post"
        action={`/auth/${provider}/link-merge`}
        reloadDocument
      >
        <button
          type="submit"
          className="bg-amber-600 text-white py-2 px-4 rounded hover:bg-amber-700"
        >
          Merge accounts
        </button>
        <Link className="ml-4 text-blue-600 underline" to="/dashboard">
          Cancel
        </Link>
      </Form>
    </aside>
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
