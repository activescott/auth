import type { ReactNode } from "react"
import type { RateLimitRule } from "@activescott/auth"
import type { AdminConfigLoaderData } from "./admin-handlers.js"
import type { AdminPresentationProps } from "./admin-layout.js"
import { AdminLayout } from "./admin-layout.js"
import type { AdminStyler } from "./admin-styles.js"
import { createStyler } from "./admin-styles.js"
import { formatValue, humanizeKey } from "./format.js"

const EMPTY_VALUE = "—"

/** `display: contents` so each pair participates in the parent grid directly */
const PAIR_STYLE = { display: "contents" } as const

export interface AdminConfigPageProps extends AdminPresentationProps {
  /** Whatever `adminConfigLoader` returned */
  data: AdminConfigLoaderData
  /** Page heading (default "Configuration") */
  title?: string
}

/**
 * Read-only view of how authentication is configured: the session cookie, the
 * providers and what each reveals about itself, abuse protection with defaults
 * resolved, and which store implementations are wired up.
 *
 * Everything shown here has already been redacted by `Auth.describeConfig()`
 * and each provider's own `describe()`; this component only lays it out.
 */
export function AdminConfigPage({
  data,
  title = "Configuration",
  classNames,
  includeDefaultStyles = true,
  linkComponent,
  navExtra,
}: AdminConfigPageProps) {
  const ui = createStyler(classNames, includeDefaultStyles)
  const { config, basePath } = data

  return (
    <AdminLayout
      title={title}
      basePath={basePath}
      current="config"
      classNames={classNames}
      includeDefaultStyles={includeDefaultStyles}
      linkComponent={linkComponent}
      navExtra={navExtra}
    >
      <Card title="Session" ui={ui}>
        <Definitions
          ui={ui}
          entries={[
            ["Cookie name", config.session.cookieName],
            ["Max age", config.session.maxAge],
            ["Secret", config.session.secret],
            ["Additional secrets", config.session.additionalSecretCount],
            ["Issuer", config.session.issuer ?? null],
            ["Audience", config.session.audience ?? null],
            ["Cookie secure", config.session.cookie.secure],
            ["Cookie sameSite", config.session.cookie.sameSite],
            ["Cookie domain", config.session.cookie.domain ?? null],
            ["Cookie path", config.session.cookie.path ?? null],
          ]}
        />
      </Card>

      {config.providers.map((provider) => (
        <Card
          key={provider.id}
          title={`Provider: ${provider.name} (${provider.id})`}
          ui={ui}
        >
          <Definitions
            ui={ui}
            entries={[
              ...Object.entries(provider.settings).map(
                ([key, value]): [string, unknown] => [humanizeKey(key), value],
              ),
              [
                "Routes",
                provider.routes
                  .map((route) => `${route.method} ${route.path}`)
                  .join(", "),
              ],
              ["Sent message", provider.initiateSentMessage ?? null],
            ]}
          />
        </Card>
      ))}

      <Card title="Abuse protection" ui={ui}>
        <Definitions
          ui={ui}
          entries={[
            ["Enabled", config.abuse.enabled],
            ["Per IP", formatRules(config.abuse.perIp)],
            ["Per identifier", formatRules(config.abuse.perIdentifier)],
            ["Minimum form fill seconds", config.abuse.minFormFillSeconds],
            ["Bot checks", config.abuse.botChecks.join(", ")],
            ["Blocked response", config.abuse.respondWith],
            ["Counter store", config.abuse.store],
          ]}
        />
      </Card>

      <Card title="Stores" ui={ui}>
        <Definitions
          ui={ui}
          entries={[
            ["User store", config.stores.userStore],
            ["Identity store", config.stores.identityStore],
            ["Challenge store", config.stores.challengeStore],
            ["Can list users", config.stores.capabilities.listUsers],
            [
              "Can batch identity lookups",
              config.stores.capabilities.findByUserIds,
            ],
            [
              "Can delete identities",
              config.stores.capabilities.deleteIdentity,
            ],
          ]}
        />
      </Card>
    </AdminLayout>
  )
}

/**
 * Render rate-limit rules the way they are usually spoken about: "3 per
 * minute, 10 per hour" rather than window sizes in seconds.
 */
function formatRules(rules: RateLimitRule[]): string {
  if (rules.length === 0) return "none"
  return rules
    .map((rule) => `${rule.max} per ${formatWindow(rule.windowSeconds)}`)
    .join(", ")
}

const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400

function formatWindow(seconds: number): string {
  if (seconds % SECONDS_PER_DAY === 0) {
    const days = seconds / SECONDS_PER_DAY
    return days === 1 ? "day" : `${days} days`
  }
  if (seconds % SECONDS_PER_HOUR === 0) {
    const hours = seconds / SECONDS_PER_HOUR
    return hours === 1 ? "hour" : `${hours} hours`
  }
  if (seconds % SECONDS_PER_MINUTE === 0) {
    const minutes = seconds / SECONDS_PER_MINUTE
    return minutes === 1 ? "minute" : `${minutes} minutes`
  }
  return `${seconds} seconds`
}

interface CardProps {
  title: string
  ui: AdminStyler
  children: ReactNode
}

function Card({ title, ui, children }: CardProps) {
  return (
    <section className={ui.className("card")} style={ui.style("card")}>
      <h2 className={ui.className("cardTitle")} style={ui.style("cardTitle")}>
        {title}
      </h2>
      {children}
    </section>
  )
}

interface DefinitionsProps {
  entries: [string, unknown][]
  ui: AdminStyler
}

function Definitions({ entries, ui }: DefinitionsProps) {
  return (
    <dl
      className={ui.className("definitionList")}
      style={ui.style("definitionList")}
    >
      {entries.map(([label, value]) => {
        const text = formatValue(value)
        return (
          <div key={label} style={PAIR_STYLE}>
            <dt
              className={ui.className("definitionTerm")}
              style={ui.style("definitionTerm")}
            >
              {label}
            </dt>
            <dd
              className={ui.className("definitionValue")}
              style={ui.style("definitionValue")}
            >
              {text === null || text === "" ? (
                <span
                  className={ui.className("muted")}
                  style={ui.style("muted")}
                >
                  {EMPTY_VALUE}
                </span>
              ) : (
                text
              )}
            </dd>
          </div>
        )
      })}
    </dl>
  )
}
