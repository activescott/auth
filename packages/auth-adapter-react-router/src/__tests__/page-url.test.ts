import { describe, it, expect } from "vitest"
import { pageUrl } from "../page-url.js"

const TEST_BASE_URL = "https://example.com"

function normalize(pathAndQuery: string): string {
  const url = pageUrl(new Request(`${TEST_BASE_URL}${pathAndQuery}`))
  return url.pathname + url.search
}

describe("pageUrl", () => {
  it.each([
    [
      "a navigation",
      "/docs/coach.data?_routes=root,routes/docs",
      "/docs/coach",
    ],
    ["a trailing-slash page", "/docs/coach/_.data", "/docs/coach/"],
    ["the root", "/_.data?_routes=root", "/"],
    ["the app's own query", "/docs.data?tab=2&_routes=root", "/docs?tab=2"],
  ])("strips v8 data-request details from %s", (_label, raw, page) => {
    expect(normalize(raw)).toBe(page)
  })

  it.each([
    ["the root", "/_root.data", "/"],
    ["the root under a basename", "/app/_root.data", "/app/"],
    ["a page", "/docs/coach.data", "/docs/coach"],
  ])("strips v7 data-request details from %s", (_label, raw, page) => {
    expect(normalize(raw)).toBe(page)
  })

  it("drops the valueless index param React Router adds for index routes", () => {
    expect(normalize("/projects.data?index&tab=2")).toBe("/projects?tab=2")
  })

  it("keeps an index param that carries a value", () => {
    expect(normalize("/projects.data?index=3&_routes=root")).toBe(
      "/projects?index=3",
    )
  })

  it.each([
    "/docs/coach",
    "/docs/coach/",
    "/",
    "/search?q=a%20b&tab=2",
    "/search?q=a+b",
  ])("leaves the plain document URL %s untouched", (plain) => {
    expect(normalize(plain)).toBe(plain)
  })

  it("keeps the origin", () => {
    const url = pageUrl(new Request(`${TEST_BASE_URL}/docs.data`))
    expect(url.origin).toBe(TEST_BASE_URL)
  })
})
