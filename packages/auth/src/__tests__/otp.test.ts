import { describe, it, expect } from "vitest"
import {
  generateOtpCode,
  hashOtpCode,
  verifyOtpCode,
  verifyOtpChallenge,
} from "../otp.js"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"

const DEFAULT_LENGTH = 6
const SAMPLE_SIZE = 1000
const SHA256_HEX_LENGTH = 64

describe("generateOtpCode", () => {
  it("should generate a code of the default length", () => {
    const code = generateOtpCode()
    expect(code).toHaveLength(DEFAULT_LENGTH)
  })

  it("should generate codes of a custom length", () => {
    expect(generateOtpCode(4)).toHaveLength(4)
    expect(generateOtpCode(8)).toHaveLength(8)
  })

  it("should generate only decimal digits", () => {
    for (let index = 0; index < SAMPLE_SIZE; index++) {
      expect(generateOtpCode()).toMatch(/^[0-9]{6}$/)
    }
  })

  it("should generate varied codes", () => {
    const codes = new Set(
      Array.from({ length: SAMPLE_SIZE }, () => generateOtpCode()),
    )
    // Collisions are possible but 1000 identical draws from 10^6 are not
    expect(codes.size).toBeGreaterThan(SAMPLE_SIZE / 2)
  })

  it("should produce all ten digits across a sample", () => {
    const seen = new Set<string>()
    for (let index = 0; index < SAMPLE_SIZE; index++) {
      for (const digit of generateOtpCode()) seen.add(digit)
    }
    expect(seen.size).toBe(10)
  })

  it("should reject invalid lengths", () => {
    expect(() => generateOtpCode(0)).toThrow()
    expect(() => generateOtpCode(-1)).toThrow()
    expect(() => generateOtpCode(2.5)).toThrow()
  })
})

describe("hashOtpCode", () => {
  it("should produce a hex SHA-256 digest", async () => {
    const hash = await hashOtpCode("challenge-1", "123456")
    expect(hash).toMatch(/^[0-9a-f]+$/)
    expect(hash).toHaveLength(SHA256_HEX_LENGTH)
  })

  it("should be deterministic for the same inputs", async () => {
    const first = await hashOtpCode("challenge-1", "123456")
    const second = await hashOtpCode("challenge-1", "123456")
    expect(first).toBe(second)
  })

  it("should differ for the same code under different challenge IDs", async () => {
    const first = await hashOtpCode("challenge-1", "123456")
    const second = await hashOtpCode("challenge-2", "123456")
    expect(first).not.toBe(second)
  })
})

describe("verifyOtpCode", () => {
  it("should accept the correct code", async () => {
    const hashedCode = await hashOtpCode("challenge-1", "123456")
    const result = await verifyOtpCode(
      { id: "challenge-1", hashedCode },
      "123456",
    )
    expect(result).toBe(true)
  })

  it("should reject an incorrect code", async () => {
    const hashedCode = await hashOtpCode("challenge-1", "123456")
    const result = await verifyOtpCode(
      { id: "challenge-1", hashedCode },
      "654321",
    )
    expect(result).toBe(false)
  })

  it("should reject the right code against the wrong challenge", async () => {
    const hashedCode = await hashOtpCode("challenge-1", "123456")
    const result = await verifyOtpCode(
      { id: "challenge-2", hashedCode },
      "123456",
    )
    expect(result).toBe(false)
  })

  it("should reject when the challenge has no hashed code", async () => {
    const result = await verifyOtpCode({ id: "challenge-1" }, "123456")
    expect(result).toBe(false)
  })
})

describe("verifyOtpChallenge", () => {
  async function createChallenge(store: InMemoryChallengeStore, code: string) {
    const id = crypto.randomUUID()
    return store.create({
      id,
      type: "sms",
      identifier: "+14155550100",
      hashedCode: await hashOtpCode(id, code),
      maxAttempts: 3,
      expiresAt: new Date(Date.now() + 60_000),
    })
  }

  it("should redeem a correct code and consume the challenge", async () => {
    const store = new InMemoryChallengeStore()
    const challenge = await createChallenge(store, "123456")

    const result = await verifyOtpChallenge(
      store,
      challenge.id,
      "sms",
      "123456",
    )

    expect(result.ok).toBe(true)
    expect(await store.findById(challenge.id)).toBeNull()
    store.destroy()
  })

  it("should fail with not_found for an unknown id or wrong type", async () => {
    const store = new InMemoryChallengeStore()
    const challenge = await createChallenge(store, "123456")

    const unknown = await verifyOtpChallenge(store, "nope", "sms", "123456")
    expect(unknown).toEqual({ ok: false, reason: "not_found" })

    const wrongType = await verifyOtpChallenge(
      store,
      challenge.id,
      "email",
      "123456",
    )
    expect(wrongType).toEqual({ ok: false, reason: "not_found" })
    store.destroy()
  })

  it("should fail with expired for an expired challenge", async () => {
    const store = new InMemoryChallengeStore()
    const challenge = await createChallenge(store, "123456")
    challenge.expiresAt = new Date(Date.now() - 1000)

    const result = await verifyOtpChallenge(
      store,
      challenge.id,
      "sms",
      "123456",
    )
    expect(result).toEqual({ ok: false, reason: "expired" })
    store.destroy()
  })

  it("should fail with invalid_code for a wrong code and count the attempt", async () => {
    const store = new InMemoryChallengeStore()
    const challenge = await createChallenge(store, "123456")

    const result = await verifyOtpChallenge(
      store,
      challenge.id,
      "sms",
      "000000",
    )
    expect(result).toEqual({ ok: false, reason: "invalid_code" })

    const stored = await store.findById(challenge.id)
    expect(stored?.attempts).toBe(1)
    store.destroy()
  })

  it("should rate limit after max attempts even with the correct code", async () => {
    const store = new InMemoryChallengeStore()
    const challenge = await createChallenge(store, "123456")

    for (let attempt = 0; attempt < 3; attempt++) {
      await verifyOtpChallenge(store, challenge.id, "sms", "000000")
    }

    const result = await verifyOtpChallenge(
      store,
      challenge.id,
      "sms",
      "123456",
    )
    expect(result).toEqual({ ok: false, reason: "rate_limited" })
    store.destroy()
  })
})
