import { useState } from "react"
import { Form, Link, useRevalidator } from "react-router"
import {
  useRegisterPasskey,
  useTurnstile,
} from "@activescott/auth-adapter-react-router/client"
import { requireAuth, profileAuthLoader } from "~/lib/auth.server"
import { passkeys as passkeyClient } from "~/lib/passkey.client"
import {
  AntiBotFields,
  AntiBotSubmitButton,
} from "~/components/anti-bot-fields"
import { CodeForm } from "~/components/code-form"
import type { Route } from "./+types/dashboard"

export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request)
  // identities (email and phone sign-in methods), passkeys, and linkFlow: the
  // add-a-method flow's state, read from the query string the providers
  // redirect back with (?add=, ?sent=1, ?linked=1, ?merged=1, ?error=). Link
  // initiates post to the same abuse-guarded endpoints as sign-in, so
  // linkFlow carries the same anti-bot form token the login page gets.
  return { user, ...(await profileAuthLoader(user.id, request)) }
}

type LoaderData = Route.ComponentProps["loaderData"]
type LinkableProvider = "email" | "sms"

export default function Dashboard({ loaderData }: Route.ComponentProps) {
  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      <p className="mb-4">
        Signed in as <code>{String(loaderData.user.metadata?.identifier)}</code>
      </p>
      <SignInMethods
        identities={loaderData.identities}
        linkFlow={loaderData.linkFlow}
      />
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
 * a merge-ticket cookie; linkFlow.conflict names the provider that minted
 * it, and the prompt below redeems it at /auth/{provider}/link-merge to
 * merge that account into this one.
 */
function SignInMethods({
  identities,
  linkFlow,
}: Pick<LoaderData, "identities" | "linkFlow">) {
  const { add, sent, merged, linked, conflict, error } = linkFlow

  return (
    <section className="mb-6 p-4 border rounded">
      <h2 className="font-semibold mb-2">Sign-in methods</h2>

      <ul className="mb-3 divide-y border rounded">
        {identities.map((method) => (
          <li
            key={method.id}
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

      {/* A conflict replaces the add form: the identifier is proven, and
          what is left to decide is whether to merge */}
      {conflict ? (
        <MergePrompt provider={conflict.provider} />
      ) : add === "email" ? (
        <AddEmail sent={sent} linkFlow={linkFlow} />
      ) : add === "sms" ? (
        <AddPhone sent={sent} linkFlow={linkFlow} />
      ) : (
        <nav className="flex gap-4">
          <Link className="text-blue-600 underline" to="/dashboard?add=email">
            Add an email
          </Link>
          <Link className="text-blue-600 underline" to="/dashboard?add=sms">
            Add a phone number
          </Link>
        </nav>
      )}

      {error && (
        <p className="text-red-700 mt-3" data-testid="link-error">
          Error: {error}
        </p>
      )}
    </section>
  )
}

/**
 * Where the verify step should land: back on this page with ?linked=1 (and
 * the open form's ?add= so a conflict prompt knows which provider minted
 * the merge ticket). Passed as ?redirectTo= on the verify URL — the same
 * mechanism a post-login redirect uses.
 */
function linkedRedirect(provider: LinkableProvider): string {
  return `/dashboard?add=${provider}&linked=1`
}

function verifyAction(provider: LinkableProvider): string {
  const redirectTo = encodeURIComponent(linkedRedirect(provider))
  return `/auth/${provider}/verify?redirectTo=${redirectTo}`
}

type AddMethodProps = {
  sent: boolean
  linkFlow: LoaderData["linkFlow"]
}

function AddEmail({ sent, linkFlow }: AddMethodProps) {
  const turnstile = useTurnstile(linkFlow.turnstileSiteKey)

  return (
    <div className="mt-2">
      <Form
        method="post"
        action="/auth/email/initiate"
        reloadDocument
        className="flex flex-col gap-3"
      >
        <AntiBotFields formToken={linkFlow.formToken} turnstile={turnstile} />
        {/* mode=link is what makes this attach to the signed-in account
            instead of starting a new sign-in */}
        <input type="hidden" name="mode" value="link" />
        <input
          type="hidden"
          name="redirectTo"
          value={linkedRedirect("email")}
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
        <AntiBotSubmitButton turnstile={turnstile}>
          {sent ? "Resend" : "Send confirmation"}
        </AntiBotSubmitButton>
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

function AddPhone({ sent, linkFlow }: AddMethodProps) {
  const [nationalNumber, setNationalNumber] = useState("")
  const turnstile = useTurnstile(linkFlow.turnstileSiteKey)

  return (
    <div className="mt-2">
      <Form
        method="post"
        action="/auth/sms/initiate"
        reloadDocument
        className="flex flex-col gap-3"
      >
        <AntiBotFields formToken={linkFlow.formToken} turnstile={turnstile} />
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
        <AntiBotSubmitButton turnstile={turnstile}>
          {sent ? "Resend code" : "Text me a code"}
        </AntiBotSubmitButton>
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
 * account into this one, and only at the provider that minted it; the
 * ticket expires after a few minutes, and the server re-checks this session
 * before merging.
 */
function MergePrompt({ provider }: { provider: string }) {
  return (
    <aside
      className="mt-4 p-3 border border-amber-300 bg-amber-50 text-amber-900 text-sm rounded"
      data-testid="merge-prompt"
    >
      <p className="mb-2">
        That {provider === "sms" ? "phone number" : "email"} already signs in to
        a <strong>different account</strong>. You just proved it&rsquo;s yours,
        so you can merge that account into this one — all of its sign-in methods
        will open this account afterwards.
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

function Passkeys({ passkeys }: Pick<LoaderData, "passkeys">) {
  const revalidator = useRevalidator()
  const registration = useRegisterPasskey({
    client: passkeyClient,
    // Reload the loader data so the new passkey shows in the list
    onRegistered: revalidator.revalidate,
  })

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
        onClick={registration.register}
        disabled={registration.status === "pending"}
        className="border py-2 px-4 rounded hover:bg-gray-50 dark:hover:bg-gray-800"
      >
        {passkeys.length > 0 ? "Add another passkey" : "Add a passkey"}
      </button>
      {registration.status === "added" && (
        <p className="text-green-700 mt-3">Passkey added.</p>
      )}
      {registration.status === "error" && (
        <p className="text-red-700 mt-3" data-testid="passkey-error">
          Error: {registration.error}
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
