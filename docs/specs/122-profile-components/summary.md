# Profile page components: summary

Issue #122. The profile page is plain and should look the same in every app, so it ships from `@activescott/auth-adapter-react-router/profile` instead of being copied into each one: `AccountSummary`, `SignInMethods` and `Passkeys` as separate components, and `ProfilePage` composing the three. Two apps were carrying the same page and waiting on this.

## Styling: class names per slot

Each component takes `classNames`, one class per named slot (`card`, `cardBody`, `cardTitle`, `table`, `input`, `submitButton`, `success`, ...), and falls back to a plain built-in look drawn in inline styles. A slot the app names gets its class and no inline style, because an inline style outranks any class and the app's rules would silently lose. `includeDefaultStyles={false}` drops the built-in look everywhere.

The alternatives were slots (render props for each piece) and CSS custom properties. Both consuming apps style with Bootstrap classes on otherwise plain markup, so class names per slot reproduce their current look exactly: `card mb-4` on the section, `card-body` inside it, `form-control` on inputs. Custom properties cannot express `btn btn-outline-primary`; render-prop slots would have each app writing the markup again, which is what #122 set out to stop. It also matches the admin pages (`AdminClassNames`), so the package has one styling contract rather than two.

## Decisions

- **The blocks import React but nothing from `react-router`**, like the admin pages, so one build serves v7 and v8. Links go through an optional `linkComponent` and are plain anchors without it.
- **The add-a-sign-in-method forms are plain `<form>` elements.** Each step is a document POST the auth routes answer with a redirect, which is what lets the flow's state live in the query string the providers redirect back with.
- **`addMethods` is explicit and empty by default.** The components run in the browser and cannot ask `Auth` which providers have an initiate route, and offering one that does not exist would link to a 404. The known ids fill in the rest: `sms` is a phone number, anything else is an email address.
- **`allowMerge` is off by default.** An app whose `UserStore.onMerge` throws would otherwise offer a button that always fails; without it an `IDENTITY_CONFLICT` reads as an error. `mergeDescription` covers what merging does to the app's own data.
- **Copy is the library's**, not a prop per string. Consistency across apps is the point of the issue; `noun` and `addLabel` cover the wording that actually differs.
- **`AccountSummary` takes `entries`** as well as `email` and `memberSince`, so an app with extra rows (a handle, an approval status) keeps its own order by passing only `entries`.
- **No change to `profileAuthLoader`.** `identities`, `passkeys` and `linkFlow` already carry everything the components render from.

## Not included

The example app has no profile page; adding one is separate work. The sign-in page stays as it is: it is the page apps deviate on, which is why #122 covers the profile page alone.

## Compatibility

Additive: a new `./profile` subpath export and nothing else. No existing export changes, per #103's constraint.
