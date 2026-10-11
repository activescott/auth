const HTTP_BAD_REQUEST = 400

/** Largest form or JSON body the endpoints read. */
export const MAX_BODY_BYTES = 16 * 1024

const NO_STORE = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
}

/** A JSON response that caches must not keep (RFC 6749 §5.1). */
export function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...NO_STORE, ...headers },
  })
}

/** An RFC 6749 §5.2 error response. */
export function oauthError(
  error: string,
  description: string,
  status = HTTP_BAD_REQUEST,
  headers: Record<string, string> = {},
): Response {
  return jsonResponse(
    { error, error_description: description },
    status,
    headers,
  )
}

/**
 * Read a body as text, refusing anything over {@link MAX_BODY_BYTES}. Returns
 * null when it is too large.
 */
export async function readBodyText(request: Request): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") ?? "0")
  if (declared > MAX_BODY_BYTES) return null
  if (!request.body) return ""
  // Counted while streaming: a chunked body has no content-length to trust.
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let received = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    received += value.byteLength
    if (received > MAX_BODY_BYTES) {
      await reader.cancel()
      return null
    }
    chunks.push(value)
  }
  const body = new Uint8Array(received)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(body)
}

/** The media type of a request, lowercased, without parameters. */
export function mediaType(request: Request): string {
  return (request.headers.get("content-type") ?? "")
    .split(";")[0]!
    .trim()
    .toLowerCase()
}

/**
 * Parse URL-encoded parameters into single values. Returns the name of the
 * first parameter sent more than once instead, since RFC 6749 §3.1 and §3.2
 * forbid repeating one.
 */
export function singleValuedParams(
  params: URLSearchParams,
  repeatable: ReadonlySet<string> = new Set(),
): { values: Map<string, string> } | { repeated: string } {
  const values = new Map<string, string>()
  for (const [name, value] of params) {
    if (repeatable.has(name)) continue
    if (values.has(name)) return { repeated: name }
    values.set(name, value)
  }
  return { values }
}

/** Return a copy of `response` with `headers` added. */
export function withHeaders(
  response: Response,
  headers: Record<string, string>,
): Response {
  const copy = new Response(response.body, response)
  for (const [name, value] of Object.entries(headers)) {
    copy.headers.set(name, value)
  }
  return copy
}
