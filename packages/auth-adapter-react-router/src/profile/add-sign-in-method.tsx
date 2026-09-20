import { FORM_TOKEN_FIELD } from "@activescott/auth"
import type { LinkFlow, SignInMethod } from "../page-loaders.js"
import { useOtpAutoSubmit } from "../client/use-otp-auto-submit.js"
import { usePreservedInput } from "../client/use-preserved-input.js"
import { useTurnstile } from "../client/use-turnstile.js"
import type { TurnstileState } from "../client/use-turnstile.js"
import type { ProfileLinkComponent } from "./profile-chrome.js"
import { Notice, ProfileLink } from "./profile-chrome.js"
import type { ProfileStyler } from "./profile-styles.js"

/**
 * A provider the profile page offers to add. The known ids fill themselves in:
 * `sms` is a phone number, anything else is an email address.
 */
export interface AddableSignInMethod {
  /** Provider id, matching the route at `/auth/{provider}/initiate` */
  provider: string
  /** Which field the form asks for (default "tel" for `sms`, else "email") */
  kind?: "email" | "tel"
  /** What the user calls it (default "phone number" or "email address") */
  noun?: string
  /** Form field the provider's initiate reads (default "phone" or "email") */
  field?: string
  /**
   * Country calling code shown as a fixed prefix on a `tel` field, e.g. "+1".
   * The visible input then takes the national number and the form submits the
   * full E.164 value, so everything downstream sees one canonical form. Without
   * it the user types the whole number themselves.
   */
  callingCode?: string
  /** Label of the link that opens the form (default `Add an email address`) */
  addLabel?: string
  /** Placeholder for the input */
  placeholder?: string
  /** Offer it even when the account already signs in with this provider */
  allowMultiple?: boolean
}

interface ResolvedMethod {
  provider: string
  kind: "email" | "tel"
  noun: string
  field: string
  callingCode: string | null
  addLabel: string
  placeholder: string
  allowMultiple: boolean
}

const SMS_PROVIDER_ID = "sms"

function resolveMethod(method: AddableSignInMethod): ResolvedMethod {
  const kind =
    method.kind ?? (method.provider === SMS_PROVIDER_ID ? "tel" : "email")
  const noun =
    method.noun ?? (kind === "tel" ? "phone number" : "email address")
  const article = /^[aeiou]/i.test(noun) ? "an" : "a"
  return {
    provider: method.provider,
    kind,
    noun,
    field: method.field ?? (kind === "tel" ? "phone" : "email"),
    callingCode: method.callingCode ?? null,
    addLabel: method.addLabel ?? `Add ${article} ${noun}`,
    placeholder:
      method.placeholder ??
      (kind === "tel" ? "415 555 0100" : "you@example.com"),
    allowMultiple: method.allowMultiple ?? false,
  }
}

/**
 * What the user calls this provider's identifier, for a message about it.
 * Falls back to the defaults for the id when the provider is not one the page
 * offers to add.
 */
export function methodNoun(
  provider: string,
  methods: AddableSignInMethod[],
): string {
  const configured = methods.find((method) => method.provider === provider)
  return resolveMethod(configured ?? { provider }).noun
}

export interface AddSignInMethodProps {
  methods: AddableSignInMethod[]
  identities: SignInMethod[]
  linkFlow: LinkFlow
  /** Path of the page these blocks render on */
  profilePath: string
  /** Where the auth routes are mounted */
  authBasePath: string
  /** Digits in the one-time code */
  codeLength: number
  /** Id of the error message the open form's input points at, if one is shown */
  errorId?: string
  ui: ProfileStyler
  linkComponent?: ProfileLinkComponent
}

/**
 * Either the open add-a-sign-in-method form, or the links that open one. Which
 * form is open travels in the query string as `?add=`, because the providers
 * redirect the browser back here between the two steps.
 */
export function AddSignInMethod({
  methods,
  identities,
  linkFlow,
  profilePath,
  authBasePath,
  codeLength,
  errorId,
  ui,
  linkComponent,
}: AddSignInMethodProps) {
  const resolved = methods.map(resolveMethod)
  // A finished flow closes its form. `?add=` outlives the flow on purpose,
  // since it is what attributes a conflict to the provider that raised it, so
  // the outcome decides this rather than the query.
  const finished = linkFlow.linked || linkFlow.merged
  const open = finished
    ? undefined
    : resolved.find((method) => method.provider === linkFlow.add)
  if (open) {
    return (
      <AddMethodForm
        method={open}
        linkFlow={linkFlow}
        profilePath={profilePath}
        authBasePath={authBasePath}
        codeLength={codeLength}
        errorId={errorId}
        ui={ui}
        linkComponent={linkComponent}
      />
    )
  }

  const offered = resolved.filter(
    (method) =>
      method.allowMultiple ||
      !identities.some((identity) => identity.provider === method.provider),
  )
  if (offered.length === 0) return null

  return (
    <div className={ui.className("actions")} style={ui.style("actions")}>
      {offered.map((method) => (
        <ProfileLink
          key={method.provider}
          to={`${profilePath}?add=${method.provider}`}
          slot="addButton"
          ui={ui}
          linkComponent={linkComponent}
        >
          {method.addLabel}
        </ProfileLink>
      ))}
    </div>
  )
}

interface AddMethodFormProps {
  method: ResolvedMethod
  linkFlow: LinkFlow
  profilePath: string
  authBasePath: string
  codeLength: number
  errorId?: string
  ui: ProfileStyler
  linkComponent?: ProfileLinkComponent
}

/**
 * Two-step flow adding an identifier to the signed-in account: the initiate
 * form posts `mode=link`, which binds the challenge to this session instead of
 * signing in as the identifier, and the code form below redeems it.
 *
 * The forms are plain `<form>` elements rather than the router's, so each step
 * is a document POST the auth routes answer with a redirect. That is what lets
 * the flow's state live in the URL.
 */
function AddMethodForm({
  method,
  linkFlow,
  profilePath,
  authBasePath,
  codeLength,
  errorId,
  ui,
  linkComponent,
}: AddMethodFormProps) {
  const turnstile = useTurnstile(linkFlow.turnstileSiteKey)
  // The page reloads on the way back from the provider; this brings what was
  // typed back, so a resend or a retry needs no retyping.
  const [value, setValue, save] = usePreservedInput(
    `profile.${method.provider}`,
  )
  const inputId = `link-${method.provider}`
  // Keeping ?add= on the destination is what attributes a conflict to the
  // provider that raised it: the loader reads the provider from the query.
  const linkedRedirect = `${profilePath}?add=${method.provider}&linked=1`
  const isEmail = method.kind === "email"
  // Which field the message is about: once the code is out it is the code that
  // was rejected, before that it is the identifier the initiate refused.
  const identifierError = linkFlow.sent ? undefined : errorId
  const codeError = linkFlow.sent ? errorId : undefined

  return (
    <div data-testid={`add-${method.provider}`}>
      <h3 className={ui.className("subheading")} style={ui.style("subheading")}>
        {method.addLabel}
      </h3>
      <form
        method="post"
        action={`${authBasePath}/${method.provider}/initiate`}
        onSubmit={save}
      >
        <input
          type="hidden"
          name={FORM_TOKEN_FIELD}
          value={linkFlow.formToken}
        />
        <input type="hidden" name="mode" value="link" />
        <input type="hidden" name="redirectTo" value={linkedRedirect} />

        <div className={ui.className("field")} style={ui.style("field")}>
          <label
            htmlFor={inputId}
            className={ui.className("label")}
            style={ui.style("label")}
          >
            {isEmail ? "Email address" : "Mobile phone number"}
          </label>
          {method.callingCode ? (
            <div
              className={ui.className("inputGroup")}
              style={ui.style("inputGroup")}
            >
              <span
                className={ui.className("inputGroupText")}
                style={ui.style("inputGroupText")}
              >
                {method.callingCode}
              </span>
              {/* No name attribute: the hidden E.164 field below is what posts */}
              <input
                type="tel"
                id={inputId}
                className={ui.className("input")}
                style={ui.style("input")}
                autoComplete="tel-national"
                inputMode="tel"
                required
                aria-invalid={identifierError ? true : undefined}
                aria-describedby={identifierError}
                placeholder={method.placeholder}
                value={value}
                onChange={(event) => setValue(event.target.value)}
              />
              <input
                type="hidden"
                name={method.field}
                value={`${method.callingCode}${value}`}
              />
            </div>
          ) : (
            <input
              type={isEmail ? "email" : "tel"}
              id={inputId}
              name={method.field}
              className={ui.className("input")}
              style={ui.style("input")}
              autoComplete={isEmail ? "email" : "tel"}
              inputMode={isEmail ? undefined : "tel"}
              required
              aria-invalid={identifierError ? true : undefined}
              aria-describedby={identifierError}
              // type="email" alone accepts dotless domains like "you@example";
              // require a dot so a typo fails here instead of after a round trip
              pattern={isEmail ? ".+@.+\\..+" : undefined}
              title={
                isEmail
                  ? "Enter a full email address like you@example.com"
                  : undefined
              }
              placeholder={method.placeholder}
              value={value}
              onChange={(event) => setValue(event.target.value)}
            />
          )}
        </div>

        <TurnstileWidget turnstile={turnstile} ui={ui} />

        {turnstile.status === "failed" ? (
          <Notice tone="warning" ui={ui} testId="turnstile-stalled">
            The bot check couldn&apos;t finish loading. Reload the page to try
            again; tracking protection or a browser extension can block it.
          </Notice>
        ) : (
          <div className={ui.className("actions")} style={ui.style("actions")}>
            <button
              type="submit"
              className={ui.className("submitButton")}
              style={ui.style("submitButton")}
              disabled={!turnstile.ready}
            >
              {submitLabel(method, linkFlow.sent, turnstile.ready)}
            </button>
            <ProfileLink
              to={profilePath}
              slot="cancelButton"
              ui={ui}
              linkComponent={linkComponent}
            >
              Cancel
            </ProfileLink>
          </div>
        )}
      </form>

      {linkFlow.sent && (
        <>
          {/* An error (a wrong code) replaces the notice; the code form stays
              for the retry */}
          {!linkFlow.errorCode && (
            <Notice tone="success" ui={ui} testId="link-sent">
              {isEmail
                ? "Check your email for a confirmation link and code."
                : "We texted you a code."}
            </Notice>
          )}
          <CodeForm
            method={method}
            action={`${authBasePath}/${method.provider}/verify?redirectTo=${encodeURIComponent(linkedRedirect)}`}
            codeLength={codeLength}
            errorId={codeError}
            ui={ui}
          />
        </>
      )}
    </div>
  )
}

function submitLabel(
  method: ResolvedMethod,
  sent: boolean,
  ready: boolean,
): string {
  if (!ready) return "Verifying you're human…"
  if (method.kind === "tel") return sent ? "Resend code" : "Text me a code"
  return sent ? "Resend email" : "Send a confirmation email"
}

interface CodeFormProps {
  method: ResolvedMethod
  action: string
  codeLength: number
  errorId?: string
  ui: ProfileStyler
}

/**
 * The one-time code that finishes the add flow. `useOtpAutoSubmit` supplies
 * the attributes platform autofill looks for and submits the form once the
 * last digit lands, so a code offered from Mail or Messages needs no button
 * press; the button stays for the cases autofill misses.
 */
function CodeForm({ method, action, codeLength, errorId, ui }: CodeFormProps) {
  const { inputProps, submitting } = useOtpAutoSubmit(codeLength)
  const inputId = `link-code-${method.provider}`

  return (
    <form method="post" action={action}>
      <div className={ui.className("field")} style={ui.style("field")}>
        <label
          htmlFor={inputId}
          className={ui.className("label")}
          style={ui.style("label")}
        >
          {method.kind === "tel"
            ? "Enter the code from the text"
            : "Enter the code from the email"}
        </label>
        <input
          type="text"
          id={inputId}
          className={ui.className("input")}
          style={ui.style("input")}
          required
          aria-invalid={errorId ? true : undefined}
          aria-describedby={errorId}
          {...inputProps}
        />
      </div>
      <button
        type="submit"
        className={ui.className("submitButton")}
        style={ui.style("submitButton")}
        disabled={submitting}
      >
        {submitting ? "Verifying…" : "Verify code"}
      </button>
    </form>
  )
}

/**
 * Where `useTurnstile` renders the widget. It posts a cf-turnstile-response
 * field the server verifies, so it has to sit inside the form it protects.
 */
function TurnstileWidget({
  turnstile,
  ui,
}: {
  turnstile: TurnstileState
  ui: ProfileStyler
}) {
  if (!turnstile.enabled) return null
  return (
    <div className={ui.className("turnstile")} style={ui.style("turnstile")}>
      <div ref={turnstile.containerRef} />
    </div>
  )
}
