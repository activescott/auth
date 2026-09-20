/**
 * UTC calendar date (yyyy-mm-dd).
 *
 * Deliberately not `toLocaleDateString`: the server and the browser can sit in
 * different timezones, and a hydration mismatch here makes React re-render the
 * whole page client side, replacing DOM nodes mid-interaction and swallowing
 * clicks on the forms these blocks render.
 */
export function formatProfileDate(value: string | Date): string {
  return new Date(value).toISOString().slice(0, "yyyy-mm-dd".length)
}
