import type {
  AuthUser,
  Identity,
  IdentityStore,
  UserStore,
} from "@activescott/auth"

/** IdentityStore and UserStore backed by arrays, for driving Auth end to end */
export function createMemoryStores(): {
  identityStore: IdentityStore
  userStore: UserStore
  identities: Identity[]
  users: AuthUser[]
  linked: Identity[]
} {
  const identities: Identity[] = []
  const users: AuthUser[] = []
  const linked: Identity[] = []

  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: async (provider, identifier) =>
      identities.find(
        (identity) =>
          identity.provider === provider && identity.identifier === identifier,
      ) ?? null,
    findByUserId: async (userId) =>
      identities.filter((identity) => identity.userId === userId),
    create: async (data) => {
      const identity: Identity = {
        id: `identity-${identities.length + 1}`,
        createdAt: new Date(),
        ...data,
      }
      identities.push(identity)
      return identity
    },
    update: async (id, data) => {
      const identity = identities.find((candidate) => candidate.id === id)
      if (!identity) throw new Error(`No identity ${id}`)
      Object.assign(identity, data)
      return { ...identity }
    },
    delete: async (id) => {
      const index = identities.findIndex((candidate) => candidate.id === id)
      if (index !== -1) identities.splice(index, 1)
    },
    reassignByUserId: async (fromUserId, toUserId) => {
      for (const identity of identities) {
        if (identity.userId === fromUserId) identity.userId = toUserId
      }
    },
  }

  const userStore: UserStore = {
    findById: async (id) => users.find((user) => user.id === id) ?? null,
    create: async () => {
      const user = { id: `user-${users.length + 1}` }
      users.push(user)
      return user
    },
    onMerge: async () => {},
    onIdentityLinked: async (_user, identity) => {
      linked.push(identity)
    },
  }

  return { identityStore, userStore, identities, users, linked }
}
