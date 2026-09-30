/**
 * The admin users page, in full. Everything visible — the table, sorting,
 * paging, the identity column — comes from the adapter; this file wires the
 * loader to the component and adds a few app-owned touches:
 *
 * - tabs that filter by sign-in method or waitlist status, using
 *   `?filter.signedUpWith=` and `?filter.approvalStatus=`. The library passes
 *   those straight to `userStore.listUsers`, so the count and the pager
 *   describe the filtered set rather than one fetched page.
 * - Approve and Block buttons in `rowActions`. They post to this route's own
 *   `action`, which checks the caller is an admin and hands the form to
 *   `waitlist.handleAdminAction`.
 * - `Link` as `linkComponent`, so sort and pagination links navigate
 *   client-side. Leave it out and the page still works with plain anchors.
 */
import { Form, Link } from "react-router"
import { adminUsersLoader, requireAdmin, waitlist } from "~/lib/auth.server"
import { adminMetadataColumns } from "~/lib/admin-columns"
import { AdminUsersPage } from "@activescott/auth-adapter-react-router/admin"
import type { AdminUserRow } from "@activescott/auth/admin"
import type { Route } from "./+types/admin.users"

export function meta() {
  return [
    { title: "Users · Admin" },
    { name: "robots", content: "noindex, nofollow" },
  ]
}

export function loader({ request }: Route.LoaderArgs) {
  return adminUsersLoader({ request })
}

export async function action({ request }: Route.ActionArgs) {
  const admin = await requireAdmin(request)
  const formData = await request.formData()
  // Blocking yourself logs you out on the next request, with nobody left to
  // undo it
  if (
    formData.get("intent") === "block" &&
    formData.get("userId") === admin.id
  ) {
    return { success: false as const, error: "You cannot block yourself" }
  }
  return waitlist.handleAdminAction(formData)
}

const TABS = [
  { label: "All", filter: undefined },
  { label: "Email", filter: "signedUpWith=email" },
  { label: "SMS", filter: "signedUpWith=sms" },
  { label: "Waiting", filter: "approvalStatus=PENDING" },
  { label: "Blocked", filter: "approvalStatus=BLOCKED" },
]

/**
 * Only the buttons that change something: no Approve on an approved user, no
 * Block on a blocked one.
 */
function WaitlistActions({ row }: { row: AdminUserRow }) {
  const status = row.metadata.approvalStatus
  return (
    <Form method="post" className="flex gap-2">
      <input type="hidden" name="userId" value={row.id} />
      {status !== "APPROVED" && (
        <button name="intent" value="approve" className="underline">
          Approve
        </button>
      )}
      {status !== "BLOCKED" && (
        <button name="intent" value="block" className="underline">
          Block
        </button>
      )}
    </Form>
  )
}

export default function AdminUsers({
  loaderData,
  actionData,
}: Route.ComponentProps) {
  const active = Object.entries(loaderData.filter)
    .map(([key, value]) => `${key}=${value}`)
    .join("&")

  return (
    <>
      {actionData && !actionData.success && (
        <p className="text-red-700 p-4">Error: {actionData.error}</p>
      )}
      <AdminUsersPage
        data={loaderData}
        metadataColumns={adminMetadataColumns}
        linkComponent={Link}
        rowActions={(row) => <WaitlistActions row={row} />}
        navExtra={TABS.map((tab) => (
          <Link
            key={tab.label}
            to={
              tab.filter ? `/admin/users?filter.${tab.filter}` : "/admin/users"
            }
            style={{ fontWeight: active === (tab.filter ?? "") ? 700 : 400 }}
          >
            {tab.label}
          </Link>
        ))}
      />
    </>
  )
}
