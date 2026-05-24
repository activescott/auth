/**
 * Read a provider's enabled state from an environment variable.
 *
 * Checks `AUTH_<PROVIDER_ID_UPPER>_ENABLED` (e.g. `AUTH_GOOGLE_ENABLED`).
 * Returns `defaultValue` (default: `true`) when the variable is not set.
 * Treats `"true"` and `"1"` as enabled; anything else as disabled.
 *
 * @example
 * ```ts
 * import { isProviderEnabled } from '@activescott/auth';
 *
 * new GoogleProvider({
 *   enabled: isProviderEnabled('google'),
 *   clientId: process.env.GOOGLE_CLIENT_ID!,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
 *   oauthStateSecret: process.env.OAUTH_STATE_SECRET!,
 * })
 * ```
 *
 * Environment variable convention:
 * ```
 * AUTH_EMAIL_ENABLED=true
 * AUTH_GOOGLE_ENABLED=true
 * AUTH_GITHUB_ENABLED=false
 * ```
 */
export function isProviderEnabled(id: string, defaultValue = true): boolean {
  const key = `AUTH_${id.toUpperCase().replace(/-/g, '_')}_ENABLED`;
  const value = process.env[key];
  if (value === undefined) return defaultValue;
  return value === 'true' || value === '1';
}
