# Cloud subscription panel

- [ ] Reproduce colleague's missing panel with their URL/build (requested).
- [ ] Display signed-in account subscription status independently of drive sync.
- [ ] Flatten Cloud Server row within provider section.
- [ ] Add authoritative team membership/editor counts; billing API currently lacks these.
- [ ] Replace 10 GB per-drive quota with agreed 50 GB team pool before promising it in UI.
- [ ] Verify translations, types and browser states before deploying.

The subscription belongs to an account today; do not infer a colleague's billing access from drive write access. Never show a fabricated 3/5 editor count. A missing provider URL currently hides the entire section.

## Invitation and profile flow (2026-09-08)

- [x] Shared full-name and optional cropped-picture step before creating a link invite and before accepting one.
- [x] Keep FOSS link invitations independent of SaaS/email.
- [x] Preserve new-user secret backup; remove duplicate name field after profile setup.
- [x] Reuse saved profile name when creating the invitee's personal drive.
- [x] Verify cropped picture upload, profile metadata and image download from a colleague's account.
- [ ] Connect SaaS email team membership invitation to drive authorization in one journey.
- [ ] Enforce link invitation usage limits in the signed token and server transaction.
- [ ] Complete paid extra-editor approval before activation.
- [ ] Staging deployment after integration checks.

The SaaS team invitation ledger and email sender are a draft. Accepting a team invitation currently does not grant drive access. Do not describe this as the completed co-worker flow or deploy it as such.

Validation: Chromium authorization/invite (new and existing users, cropped avatar upload and recipient download) and chatroom pass, including strict browser diagnostics. Profile screen inspected in the local in-app browser.

## Team onboarding

- [x] Show editor-seat policy beside edit permission in the SaaS invite UI; keep FOSS free of billing copy.
- [ ] Reuse one invitation step for Share and onboarding: create a team drive, invite colleagues (optional), open the drive.
- [ ] Only nudge for a profile when there is no avatar; reuse existing full name and photo.
- [ ] Show actual team seat counts from the billing API; do not infer them from a drive's write list.
- [ ] Activate membership/drive access together on acceptance; existing editors count once and viewers are free.
- [ ] Require owner approval before adding a paid seat above the allowance.

The onboarding entry belongs after account/profile setup or choosing Cloud Server.
It creates a work drive rather than sharing the identity's private drive.
Invitation creation alone is not acceptance and must not consume a seat.
