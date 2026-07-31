import { describe, it, expect } from "vitest"
import { generateOtpCode, hashOtpCode, verifyOtpCode } from "../otp.js"

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
