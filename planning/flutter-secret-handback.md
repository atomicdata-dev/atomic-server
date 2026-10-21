# Flutter sign-in: the browser unlocks the backup and hands the secret back

Joep chose this on 21 Oct 2026 ("Bouwen"). Background and the other options:
`/mnt/project-files/signin-overview/overview.md` (project files).

## Problem

"Sign in with atomic.place" in the Flutter app can only open an
`atomic-assisted` backup wrapper. Backups made before 5 Oct 2026 (and some
others) hold only `webauthn-prf` / `recovery-code` wrappers, which only the
web app can open. Those users (Joep, Polle) hit a dead end.

## Design

The server stays blind: it relays only ciphertext sealed to a key that exists
only in the app's memory. Secret sign-in by backup is NOT introduced; account
lookup by agent stays on proven `AGENT_LINKS` only.

1. **App starts a link with its key.** The app makes an ephemeral X25519 key
   pair (in memory, one per attempt) and calls `POST /api/device-link` with the
   existing fields plus `app_key` (base64url, 32 bytes raw X25519 public key).
   It opens `https://app.atomic.place/app/send-identity?code=<user_code>` in
   the system browser and shows the user code with "Check that the browser
   shows this code".
2. **Browser shows what it is about to do.** The data-browser route
   `/app/send-identity` needs an account session (same sign-in panel as the
   restore step). It reads the link with `GET /api/device-link/code/{code}`,
   which now also returns `app_key` (and already returns the device name).
   It shows: "Send your identity to <device name>? Only continue if you
   started this on your own device just now and it shows code <ABCD-1234>."
   with an explicit Send button. No automatic send.
3. **Browser unlocks the backup** with the existing restore code
   (`recovery.ts`): assisted if present, else passkey, else recovery code,
   v1 password. It checks the unlocked agent equals the backup's
   `agent_subject`. After a passkey/code unlock it keeps the existing
   background `appendAssistedWrapper`, so later sign-ins work directly.
4. **Browser seals the secret to the app.** Ephemeral sender X25519 key,
   ECDH with `app_key`, HKDF-SHA256 (salt: empty, info:
   `"atomic-identity-handback-v1" || app_key || sender_pub`), 32-byte key,
   AES-256-GCM with a random 12-byte nonce. Plaintext: JSON
   `{"secret": ..., "subject": ..., "drive": ...|null}`. Sends
   `POST /api/device-link/code/{code}/identity` with
   `{"epk", "nonce", "ciphertext"}` (base64url), cookie session required.
5. **Server stores and approves.** The endpoint requires the cookie session,
   a pending, unexpired link that has an `app_key`, and stores the sealed blob
   once (a second deposit is refused). It approves the link for that account
   as `approve` does. Bounded size (ciphertext <= 4 KiB). Rate limited like the
   approve endpoint.
6. **App collects.** The existing poll `GET /api/device-link/{device_code}`
   returns the session plus `sealed_identity` once. The app derives the same
   key, decrypts, checks the secret's public key matches `subject`, saves the
   session and signs in with the secret. The private key is dropped.

## Threats

- A hostile link (attacker's own `app_key`) is the phishing risk. Mitigations:
  the confirmation screen names the device and the code, says to continue only
  if the person started it themselves, and needs a press. Same level as the
  existing "Connect this device" press. The secret never travels in a URL.
- The server, logs and backups see only ciphertext.
- Replays: the sealed blob is delivered once and the link expires as before.

## Work

- [ ] atomic-saas: `app_key` on device-link request, returned by code lookup;
      deposit endpoint; poll returns `sealed_identity`; tests.
- [ ] data-browser: `/app/send-identity` route reusing restore UI + sealing; vitest
      for the seal against a fixed vector.
- [ ] atomic_flutter: X25519 + open + verify (`cryptography` package), same vector.
- [ ] Flutter login: use it for "Sign in with atomic.place"; keep
      `AtomicNoAssistedRecovery` paste fallback for old portals.
- [ ] Shared test vector in `planning/` or a fixtures file used by both sides.
