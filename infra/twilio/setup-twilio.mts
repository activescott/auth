#!/usr/bin/env node
/* eslint-disable no-console */
import { createInterface } from "node:readline/promises"
import { writeFileSync, existsSync, readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"

/**
 * Interactive Twilio provisioning for SMS auth. Prompts for credentials,
 * verifies them, helps you pick (or buy) a number or a Messaging Service,
 * and writes the result to a .env file. Manual steps that can't be
 * scripted (RCS onboarding, toll-free verification) are printed as a
 * checklist at the end.
 *
 * Usage: ./infra/twilio/setup-twilio.mts [path/to/.env]
 * The default target is the example app's .env; pass a path to write your
 * own app's env file instead.
 */

const API = "https://api.twilio.com/2010-04-01"
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..")
const envPath = resolve(
  process.argv[2] ?? resolve(repoRoot, "examples/react-router/.env"),
)

async function question(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    return await rl.question(prompt)
  } finally {
    rl.close()
  }
}

/**
 * Prompts without echoing the typed value; each character is shown as `*`.
 * Reads stdin in raw mode so the secret never appears in the terminal or
 * scrollback. Falls back to a plain non-echoing read when stdin is not a
 * TTY (e.g. piped input).
 */
function questionHidden(prompt: string): Promise<string> {
  return new Promise((resolvePromise) => {
    const stdin = process.stdin
    const wasRaw = stdin.isTTY ? stdin.isRaw : false
    // Raw mode (and its echo-off) must be on before the prompt is shown, or
    // input arriving the instant the prompt appears would still be echoed.
    if (stdin.isTTY) stdin.setRawMode(true)
    stdin.resume()
    process.stdout.write(prompt)
    let value = ""
    let settled = false
    function finish(): void {
      if (settled) return
      settled = true
      stdin.removeListener("data", onData)
      stdin.removeListener("end", finish)
      if (stdin.isTTY) stdin.setRawMode(wasRaw)
      stdin.pause()
      process.stdout.write("\n")
      resolvePromise(value)
    }
    function onData(chunk: Buffer): void {
      // Escape sequences some terminals inject around pasted text
      // (bracketed-paste markers, cursor moves) must not become part of the
      // secret; strip them, then drop any leftover control characters.
      const text = chunk.toString("utf8").replace(/\x1b\[[0-9;]*[A-Za-z~]/g, "")
      for (const char of text) {
        if (char === "\r" || char === "\n") return finish()
        if (char === "\u0003") {
          // Ctrl-C
          if (stdin.isTTY) stdin.setRawMode(wasRaw)
          process.stdout.write("\n")
          process.exit(130)
        }
        if (char === "\u007f" || char === "\b") {
          if (value.length > 0) {
            value = value.slice(0, -1)
            process.stdout.write("\b \b")
          }
          continue
        }
        if (char < " ") continue
        value += char
        process.stdout.write("*")
      }
    }
    stdin.on("data", onData)
    stdin.once("end", finish)
  })
}

function twilioFetch(
  sid: string,
  token: string,
  path: string,
  init?: RequestInit,
): Promise<Response> {
  return fetch(`${API}/Accounts/${sid}${path}`, {
    ...init,
    headers: {
      Authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString("base64")}`,
      ...(init?.method === "POST"
        ? { "Content-Type": "application/x-www-form-urlencoded" }
        : {}),
      ...init?.headers,
    },
  })
}

async function main(): Promise<void> {
  console.log("Twilio setup for the SMS auth example\n")
  console.log("You need a Twilio account (https://www.twilio.com/try-twilio).")
  console.log(
    "Find your Account SID and Auth Token at https://console.twilio.com\n",
  )

  const accountSid = (await question("Account SID (AC...): ")).trim()
  const authToken = (
    await questionHidden("Auth Token (input hidden, shown as *): ")
  ).trim()
  if (!/^[0-9a-f]{32}$/.test(authToken)) {
    console.warn(
      `note: read ${authToken.length} characters, but Twilio auth tokens are 32 hex characters — the paste may have been clipped.`,
    )
  }

  process.stdout.write("Verifying credentials... ")
  const account = await twilioFetch(accountSid, authToken, ".json")
  if (!account.ok) {
    console.error(`failed (${account.status}). Check the SID/token.`)
    console.error(await account.text())
    if (account.status === 401) {
      console.error(`
Twilio returns the same 401 (error 20003) for wrong credentials AND for a
suspended account (e.g. out of funds) — even when the console shows these
exact credentials. If you copied them straight from the console, check for
a suspension notice at https://www.twilio.com/console/projects/summary
(it may not appear anywhere else). https://www.twilio.com/docs/errors/20003`)
    }
    process.exit(1)
  }
  console.log("ok\n")

  // Existing numbers
  const numbersResponse = await twilioFetch(
    accountSid,
    authToken,
    "/IncomingPhoneNumbers.json?PageSize=20",
  )
  const numbersJson = (await numbersResponse.json()) as {
    incoming_phone_numbers?: Array<{ phone_number: string }>
  }
  const numbers = numbersJson.incoming_phone_numbers ?? []

  let from = ""
  if (numbers.length > 0) {
    console.log("Numbers on your account:")
    for (const [index, n] of numbers.entries()) {
      console.log(`  ${index + 1}. ${n.phone_number}`)
    }
    const pick = (
      await question(
        "Use one of these? Enter its number, or press Enter to buy a new one: ",
      )
    ).trim()
    const picked = numbers[Number.parseInt(pick, 10) - 1]
    if (picked) from = picked.phone_number
  }

  if (!from) {
    const country = (
      (await question("Country code to search for a number [US]: ")).trim() ||
      "US"
    ).toUpperCase()
    const search = await twilioFetch(
      accountSid,
      authToken,
      `/AvailablePhoneNumbers/${country}/Local.json?SmsEnabled=true&PageSize=5`,
    )
    const searchJson = (await search.json()) as {
      available_phone_numbers?: Array<{ phone_number: string }>
    }
    const available = searchJson.available_phone_numbers ?? []
    if (available.length === 0) {
      console.error(`No SMS-capable numbers available in ${country}.`)
      process.exit(1)
    }
    console.log("Available numbers:")
    for (const [index, n] of available.entries()) {
      console.log(`  ${index + 1}. ${n.phone_number}`)
    }
    const pick = (
      await question(
        "Buy which number? (charges your Twilio account; Enter to abort): ",
      )
    ).trim()
    const chosen = available[Number.parseInt(pick, 10) - 1]
    if (!chosen) {
      console.log("Aborted — no number purchased.")
      process.exit(0)
    }

    const purchase = await twilioFetch(
      accountSid,
      authToken,
      "/IncomingPhoneNumbers.json",
      {
        method: "POST",
        body: new URLSearchParams({
          PhoneNumber: chosen.phone_number,
        }).toString(),
      },
    )
    if (!purchase.ok) {
      console.error(`Purchase failed (${purchase.status}):`)
      console.error(await purchase.text())
      process.exit(1)
    }
    from = chosen.phone_number
    console.log(`Purchased ${from}\n`)
  }

  const messagingServiceSid = (
    await question(
      "Messaging Service SID (MG..., optional — required for RCS; Enter to skip): ",
    )
  ).trim()

  const lines = [
    `TWILIO_ACCOUNT_SID=${accountSid}`,
    `TWILIO_AUTH_TOKEN=${authToken}`,
    messagingServiceSid
      ? `TWILIO_MESSAGING_SERVICE_SID=${messagingServiceSid}`
      : `TWILIO_FROM=${from}`,
  ]

  writeEnv(lines)
  console.log(`\nWrote ${envPath}`)

  console.log(`
Manual steps you may still need (not scriptable):
  - US numbers: register for A2P 10DLC (or use a toll-free number and
    complete toll-free verification) before carriers deliver reliably.
    https://console.twilio.com/us1/develop/sms/regulatory-compliance
  - If a text never arrives, check the per-message delivery log:
    https://console.twilio.com/us1/monitor/logs/sms
    The Twilio API accepts a message even when carriers later filter it,
    so this log is the only place the failure shows. Error 30034 there =
    the number isn't A2P 10DLC registered yet (see link above).
  - RCS (richer messages, branded sender): create a Messaging Service,
    then onboard an RCS sender to it — approval takes days to weeks:
    https://www.twilio.com/docs/rcs
    Once onboarded, set TWILIO_MESSAGING_SERVICE_SID in .env; Twilio
    delivers via RCS with automatic SMS fallback, no code changes.

Try it (from the repo root):
  npm run dev --workspace=examples/react-router
  → http://localhost:5173/login?via=sms
`)
}

function writeEnv(lines: string[]): void {
  const preserved = existsSync(envPath)
    ? readFileSync(envPath, "utf8")
        .split("\n")
        .filter(
          (line) =>
            line.trim() !== "" && !/^(SMS_TRANSPORT|TWILIO_)/.test(line.trim()),
        )
    : []
  writeFileSync(envPath, [...preserved, ...lines, ""].join("\n"))
}

await main()
