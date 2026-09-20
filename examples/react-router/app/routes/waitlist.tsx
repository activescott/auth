/**
 * Where the waitlist sends anyone without an approved account, instead of a
 * sign-in code. Deliberately calls no auth function: `onSessionVerified`
 * redirects unapproved sessions here, so checking the session on this page
 * would redirect it to itself.
 */
import { Link } from "react-router"

export function meta() {
  return [{ title: "Waitlist · RR Auth Example" }]
}

export default function Waitlist() {
  return (
    <main className="container mx-auto p-8 max-w-xl">
      <h1 className="text-3xl font-bold mb-4">You're on the waitlist</h1>
      <p className="mb-6">
        An admin has to approve your account before you can sign in. Try again
        once they have.
      </p>
      <Link to="/login" className="underline">
        Back to sign in
      </Link>
    </main>
  )
}
