# Bringing work along when you sign in as someone else

> Status: in progress (23 Oct 2026, Joep: "bouw het, met goede UX per flow").
> Builds on the proposal in project files `anonymous-identity/proposal.md`
> (option B, "meenemen"). Delegation (one person, several keys, proven) is the
> long-term fix and is not part of this.

## The problem

A person can end up with two identities (two secrets): one made in the web
app, one in a phone app, one per app. Today the second sign-in replaces the
first and the first identity's work drops out of sight:

- Web, no account: signing in with a secret overwrites the stored key. The
  old key is not even archived (`GettingStartedFlow.tsx` `handleSignInWithSecret`).
- Web, managed account: `IdentityReconcileGate` brings a demo guest's drives
  along, nothing else.
- App: you can only sign in when signed out; signing out keeps the data in the
  database but nothing lists it for the next identity.

## The one rule

When this device holds identity **A** and the person signs in as **B**, A's
work comes along:

1. A (still able to sign) adds B to `write` on every drive A can write.
2. Those drives are added to B's drive list (the `drives` list on B's home).
3. A's secret is archived on the device, never deleted.

Nothing is copied or re-signed. A's commits stay A's; B can now edit and see
everything. A's private drive comes along only when it holds something beyond
its drive list, and then shows up under A's name.

"Has work" = A can write at least one drive other than an empty private drive.
No work, no step: the sign-in is just a sign-in.

## Asking or not

- **App (own phone):** no question. The sign-in ends on one result line:
  "Your notes from before are in your account now." (with the number of
  drives), and they are in the drive switcher.
- **Web:** a browser may be shared, so one question, only when A has work:
  "Keep what you made here?" with **Bring it along** (default) and **Leave it
  here** (archives A, lists nothing). One screen, no jargon.

Words used on screen: "what you made here", "your account", "this device".
Not: agent, identity, drive rights, merge.

## The flows

| Flow | What the person does | What happens |
| --- | --- | --- |
| Site first, then a fresh app | App: Sign in (browser hand-back or paste) | Plain sign-in, nothing to bring |
| Site first, app used before signing in | App settings: "Sign in" | B signs in, A's work comes along, result line |
| App first, then the site | Site: "Sign in with secret" (copied from the app) or hand-back | Plain sign-in; if the browser had a guest with work, the question |
| Two apps used apart | App 2 settings: "Sign in", with the secret or a code from app 1 | Same as row 2 |
| Signed in as B, sign in as B again | Nothing to do | No step |

The app needs a "Sign in" entry while signed in (today the login screen is
only shown when signed out). It lives in the profile/settings screen, next to
Sign out, and opens the same sign-in options as the login screen.

## Layers

- `atomic_lib`: `bring_along(db, from: &Agent, to: &str) -> BringAlong { drives }`
  and the "has work" check, with tests (two agents, private and shared
  drives, a drive A cannot write, idempotent re-run).
- Bridge + `atomic_store_flutter`: `node.identity.signIn(secret)` brings A
  along when the node holds A with work, and reports what it brought.
  `FakeIdentity` mirrors it.
- Flutter app: "Sign in" in settings, the result line, archive of A's secret.
- Web app (TS, its own lib): the FOSS secret sign-in archives A and asks the
  question; the managed gate keeps its current behaviour but uses the same
  wording.

## Progress

- [ ] atomic_lib `bring_along` + tests
- [ ] Bridge, `node.identity`, fake, Dart tests
- [ ] App: sign in while signed in, result line, widget tests
- [ ] Web: archive + question on secret sign-in, vitest + one e2e
- [ ] Screenshots of every screen, app and web
