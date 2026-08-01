import { describe, it, expect } from "vitest"
import { InMemoryCredentialStore } from "../stores/in-memory-credential-store.js"
import type { StoredCredential } from "../types.js"

function credentialData(
  overrides: Partial<Omit<StoredCredential, "createdAt" | "lastUsedAt">> = {},
): Omit<StoredCredential, "createdAt" | "lastUsedAt"> {
  return {
    credentialId: "cred-1",
    publicKey: "cHVibGljLWtleQ",
    counter: 0,
    userId: "user-1",
    deviceType: "multiDevice",
    backedUp: true,
    ...overrides,
  }
}

describe("InMemoryCredentialStore", () => {
  it("should create and find a credential by id", async () => {
    const store = new InMemoryCredentialStore()
    const created = await store.create(credentialData())

    expect(created.createdAt).toBeInstanceOf(Date)
    expect(await store.findById("cred-1")).toEqual(created)
    expect(await store.findById("missing")).toBeNull()
  })

  it("should find all credentials for a user", async () => {
    const store = new InMemoryCredentialStore()
    await store.create(credentialData({ credentialId: "cred-1" }))
    await store.create(credentialData({ credentialId: "cred-2" }))
    await store.create(
      credentialData({ credentialId: "cred-3", userId: "user-2" }),
    )

    const found = await store.findByUserId("user-1")
    expect(found.map((credential) => credential.credentialId).sort()).toEqual([
      "cred-1",
      "cred-2",
    ])
  })

  it("should update counter and lastUsedAt", async () => {
    const store = new InMemoryCredentialStore()
    await store.create(credentialData())

    await store.updateCounterAndLastUsed("cred-1", 42)

    const updated = await store.findById("cred-1")
    expect(updated?.counter).toBe(42)
    expect(updated?.lastUsedAt).toBeInstanceOf(Date)
  })

  it("should delete a credential", async () => {
    const store = new InMemoryCredentialStore()
    await store.create(credentialData())

    await store.delete("cred-1")

    expect(await store.findById("cred-1")).toBeNull()
  })
})
