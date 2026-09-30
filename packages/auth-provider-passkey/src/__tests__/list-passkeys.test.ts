import { describe, it, expect, vi } from "vitest"
import type { Identity, IdentityStore } from "@activescott/auth"
import { listPasskeys } from "../list-passkeys.js"

function identity(overrides: Partial<Identity>): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "passkey",
    identifier: "cred-1",
    providerState: {
      publicKey: "AQID",
      counter: 3,
      deviceType: "multiDevice",
      backedUp: true,
    },
    createdAt: new Date("2026-09-01T12:00:00.000Z"),
    ...overrides,
  }
}

function storeWith(identities: Identity[]): IdentityStore {
  return {
    findByProviderAndIdentifier: vi.fn(),
    findByUserId: vi.fn(async () => identities),
    create: vi.fn(),
    update: vi.fn(),
  }
}

describe("listPasskeys", () => {
  it("summarizes each passkey identity, skipping other providers and invalid state", async () => {
    const store = storeWith([
      identity({
        providerState: {
          publicKey: "AQID",
          counter: 3,
          deviceType: "multiDevice",
          backedUp: true,
          nickname: "MacBook Touch ID",
          lastUsedAt: "2026-09-10T08:30:00.000Z",
        },
      }),
      identity({
        id: "identity-2",
        provider: "email",
        identifier: "user@example.com",
        providerState: {},
      }),
      identity({
        id: "identity-3",
        identifier: "cred-2",
        providerState: {
          publicKey: "BAUG",
          counter: 0,
          deviceType: "singleDevice",
          backedUp: false,
        },
        createdAt: new Date("2026-09-02T00:00:00.000Z"),
      }),
      identity({
        id: "identity-4",
        identifier: "cred-corrupt",
        providerState: { publicKey: "" },
      }),
    ])

    const passkeys = await listPasskeys(store, "user-1")

    expect(store.findByUserId).toHaveBeenCalledWith("user-1")
    expect(passkeys).toEqual([
      {
        credentialId: "cred-1",
        nickname: "MacBook Touch ID",
        synced: true,
        createdAt: "2026-09-01T12:00:00.000Z",
        lastUsedAt: "2026-09-10T08:30:00.000Z",
      },
      {
        credentialId: "cred-2",
        nickname: null,
        synced: false,
        createdAt: "2026-09-02T00:00:00.000Z",
        lastUsedAt: null,
      },
    ])
  })

  it("never exposes the stored public key or counter", async () => {
    const [summary] = await listPasskeys(storeWith([identity({})]), "user-1")

    expect(Object.keys(summary ?? {}).sort()).toEqual([
      "createdAt",
      "credentialId",
      "lastUsedAt",
      "nickname",
      "synced",
    ])
  })

  it("returns an empty list for a user without passkeys", async () => {
    expect(await listPasskeys(storeWith([]), "user-1")).toEqual([])
  })
})
