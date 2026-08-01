#!/usr/bin/env node
/* eslint-disable no-console */
import { createInterface } from "node:readline/promises"
import { writeFileSync, existsSync, readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  PinpointSMSVoiceV2Client,
  DescribePhoneNumbersCommand,
  DescribePoolsCommand,
  DescribeSenderIdsCommand,
} from "@aws-sdk/client-pinpoint-sms-voice-v2"

/**
 * Interactive AWS End User Messaging setup for the SMS example. Uses the
 * standard AWS credential chain (env vars, ~/.aws profile, SSO), lists
 * your origination identities (phone numbers, pools, sender IDs) to pick
 * from, and writes .env. Number/pool purchase and RCS agent registration
 * happen in the AWS console; the checklist at the end covers them.
 */

const exampleDir = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const envPath = resolve(exampleDir, ".env")

const rl = createInterface({ input: process.stdin, output: process.stdout })

async function main(): Promise<void> {
  console.log("AWS End User Messaging setup for the SMS auth example\n")
  console.log(
    "Credentials come from the standard AWS chain (aws configure / SSO / env vars).\n",
  )

  const region =
    (await rl.question("AWS region [us-east-1]: ")).trim() || "us-east-1"
  const client = new PinpointSMSVoiceV2Client({ region })

  process.stdout.write("Listing origination identities... ")
  const identities: Array<{ label: string; value: string }> = []
  try {
    const [numbers, pools, senderIds] = await Promise.all([
      client.send(new DescribePhoneNumbersCommand({ MaxResults: 20 })),
      client.send(new DescribePoolsCommand({ MaxResults: 20 })),
      client.send(new DescribeSenderIdsCommand({ MaxResults: 20 })),
    ])
    for (const n of numbers.PhoneNumbers ?? []) {
      if (n.PhoneNumber) {
        identities.push({
          label: `number ${n.PhoneNumber} (${n.NumberType ?? "?"})`,
          value: n.PhoneNumber,
        })
      }
    }
    for (const p of pools.Pools ?? []) {
      if (p.PoolId) {
        identities.push({ label: `pool ${p.PoolId}`, value: p.PoolId })
      }
    }
    for (const s of senderIds.SenderIds ?? []) {
      if (s.SenderId) {
        identities.push({ label: `sender ID ${s.SenderId}`, value: s.SenderId })
      }
    }
    console.log(`found ${identities.length}\n`)
  } catch (error) {
    console.error("failed.")
    console.error(error instanceof Error ? error.message : String(error))
    console.error(
      "\nCheck your AWS credentials/permissions (sms-voice:Describe*).",
    )
    process.exit(1)
  }

  let originationIdentity = ""
  if (identities.length > 0) {
    console.log("Origination identities in this region:")
    for (const [index, identity] of identities.entries()) {
      console.log(`  ${index + 1}. ${identity.label}`)
    }
    const pick = (
      await rl.question("Use which? Enter its number, or Enter to type one: ")
    ).trim()
    const picked = identities[Number.parseInt(pick, 10) - 1]
    if (picked) originationIdentity = picked.value
  } else {
    console.log(
      "None found. Request a phone number in the AWS console first:\n" +
        "https://console.aws.amazon.com/sms-voice/home#/phone-numbers\n",
    )
  }

  if (!originationIdentity) {
    originationIdentity = (
      await rl.question(
        "Origination identity (E.164 number, pool-..., or sender ID): ",
      )
    ).trim()
    if (!originationIdentity) {
      console.log("Aborted — nothing written.")
      process.exit(0)
    }
  }

  const configurationSet = (
    await rl.question("Configuration set name (optional, Enter to skip): ")
  ).trim()

  const lines = [
    "SMS_TRANSPORT=aws",
    `AWS_SMS_ORIGINATION_IDENTITY=${originationIdentity}`,
    `AWS_REGION=${region}`,
    ...(configurationSet
      ? [`AWS_SMS_CONFIGURATION_SET=${configurationSet}`]
      : []),
  ]

  writeEnv(lines)
  console.log(`\nWrote ${envPath}`)

  console.log(`
Manual steps you may still need (not scriptable):
  - New AWS accounts start in the SMS sandbox: only verified destination
    numbers receive texts until you request production access.
    https://docs.aws.amazon.com/sms-voice/latest/userguide/sandbox.html
  - US: register a 10DLC campaign or complete toll-free verification for
    reliable carrier delivery.
  - RCS: register an RCS agent (approval takes days to weeks), add it to
    a phone pool, and use that pool ID as AWS_SMS_ORIGINATION_IDENTITY —
    delivery falls back to SMS automatically.

Run: npm run dev   → http://localhost:5173/login
`)
  rl.close()
}

function writeEnv(lines: string[]): void {
  const preserved = existsSync(envPath)
    ? readFileSync(envPath, "utf8")
        .split("\n")
        .filter(
          (line) =>
            line.trim() !== "" &&
            !/^(SMS_TRANSPORT|AWS_SMS_|AWS_REGION)/.test(line.trim()),
        )
    : []
  writeFileSync(envPath, [...preserved, ...lines, ""].join("\n"))
}

await main()
