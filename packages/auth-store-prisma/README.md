# @activescott/auth-store-prisma

[Prisma](https://www.prisma.io/) `IdentityStore` for
[`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth).

Every app that keeps identities in Prisma writes the same adapter: map rows to
`Identity`, coerce the JSON column into a `providerState` object, write it back
on create and update. This package is that adapter. `UserStore` stays in your
app, since your user table is yours.

Zero runtime dependencies, and no dependency on `@prisma/client`: the model is
typed structurally, so it works with whatever client version you generated.

## Install

```bash
npm install @activescott/auth-store-prisma
```

## Schema

The model needs these fields (column names can differ via `@map`) and the
compound unique on `provider` and `identifier`:

```prisma
model Identity {
  id         String    @id @default(uuid())
  userId     String    @map("user_id")
  provider   String
  identifier String
  metadata   Json?
  createdAt  DateTime  @default(now()) @map("created_at")
  verifiedAt DateTime? @map("verified_at")

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([provider, identifier])
  @@map("identities")
}
```

The JSON column that holds `providerState` can have any name; `metadata` here
is the name schemas from before `@activescott/auth` v5 already use.

## Usage

```typescript
import { Auth } from "@activescott/auth"
import { createPrismaIdentityStore } from "@activescott/auth-store-prisma"
import { prisma } from "./database.server"

const auth = new Auth({
  // ...session, providers
  identityStore: createPrismaIdentityStore({
    model: prisma.identity,
    providerStateField: "metadata",
  }),
  userStore,
})
```

`providerStateField` is checked against the model's fields, so a typo fails to
compile.

## Account merge

By default `reassignByUserId` moves the identities with one `updateMany`. When
a merge must also move your own per-user data all-or-nothing, pass your own and
run the whole merge in one transaction there (see the account-merge docs in the
`@activescott/auth` README):

```typescript
createPrismaIdentityStore({
  model: prisma.identity,
  providerStateField: "metadata",
  reassignByUserId: (fromUserId, toUserId) =>
    prisma.$transaction(async (tx) => {
      await tx.identity.updateMany({
        where: { userId: fromUserId },
        data: { userId: toUserId },
      })
      // ...move app data, delete the absorbed user row
    }),
})
```

To refuse merges outright, pass one that throws.

## Behavior

| Method                        | Notes                                                             |
| ----------------------------- | ----------------------------------------------------------------- |
| `findByProviderAndIdentifier` | `findUnique` on the `provider_identifier` compound key            |
| `findByUserId`                | Newest first                                                      |
| `findByUserIds`               | One query for all users, newest first; no query for an empty list |
| `create` / `update`           | `update` leaves fields it was not given unchanged                 |
| `delete`                      | Deleting an identity that is already gone is a no-op              |

A `null` or non-object JSON value reads back as an empty `providerState`. The
same coercion is exported as `toProviderState` for code that reads identity
rows directly.

## License

MIT
