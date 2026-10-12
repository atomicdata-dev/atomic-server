# Encrypted conversations

Direct messages and group chats between agents, end-to-end encrypted
whoever hosts them. The host stores ciphertext, and still authorizes every
write, because everything authorization needs stays readable.

## What exists (first version)

- [x] `atomic_lib::conversation`: agent encryption keys, the keyring, sealing
      and opening messages, report-by-reveal of one message key.
- [x] WASM exports `conversationEncryptionKey`, `conversationAddEpoch`,
      `conversationSeal`, `conversationOpen`.
- [x] Ontology `conversations` (`lib/defaults/conversations.json`):
      `Conversation`, `SealedMessage`, `encryptionKey`, `conversationKeys`,
      `sealed`, `conversations`.
- [x] `GET /conversations`: the conversations on this server the requester is
      in, found through the reference index on `read`.
- [x] App: Messages panel in the sidebar, "Message" on every avatar menu, a
      New message dialog that takes an agent DID, the conversation page.
- [x] The app publishes the signed-in agent's `encryptionKey` at start.

## Model

- A **Conversation** is a drive of its own (`isA` `[Conversation, Drive]`),
  never inside someone's private drive or a team drive. Members get `read`
  and `append`, and nobody has `write`: a `write` on the drive would reach
  every message in it. The server grants a DID resource's creator `write` at
  genesis, so the creator removes it in a second commit. Each message sets
  `write` to its author only, so nobody can edit or replace someone else's
  ciphertext. The price: the keyring and members can't change yet, which
  epoch rotation will need (see Next).
- It is listed in the creator's private drive under `conversations`, not
  `drives`, so it never shows up as a workspace. The other members find it
  through `/conversations`; it joins their own list when they open it from an
  avatar menu or the New message dialog.
- Live updates: the conversation is a drive, so a `SUB` on it gets drive
  fan-out. The app holds one with `Store.subscribeLive` while the page is open
  (the same method as PR 1949, copied verbatim so the two merge cleanly).

## Keys

- **Agent key**: X25519, `blake3::derive_key("atomic 2026 agent conversation
  encryption key", vault_proof)`, where the vault proof is the agent's Ed25519
  signature over the fixed vault message (`helpers/managed/vault.ts`). Every
  device of the agent derives the same key, so a restored identity reads every
  past conversation. The public half is `encryptionKey` on the Agent.
- **Keyring** (`conversationKeys`, JSON): one random 32-byte key per epoch,
  wrapped to each member with an ephemeral X25519 exchange, BLAKE3 KDF and
  XChaCha20-Poly1305. The wrap is bound to the member and the epoch.
- **Sealed message** = base64url(version | epoch (4 BE) | message id (16) |
  nonce (24) | ciphertext). The per-message key is derived from the epoch key
  and the random message id (the DID subject is unknown before signing). The
  associated data is the header plus the conversation subject, so a message
  can't be replayed into another conversation.
- The payload is JSON `{text, replyTo?}`: what a `Message` carries in the
  clear.

## What the host sees

Members, who posts and when, message counts and sizes, key epochs. Not the
text. Server search, AI and previews don't work on conversations; that is the
price.

## Why not MLS

MLS needs one total order for group changes, per-device keys, and state that
can't be lost. Atomic is offline-first with one key per agent across devices.
If it is ever needed, MLS's exporter secret becomes the epoch key and
`SealedMessage` stays as it is.

## Next

- [ ] Epoch rotation when members change (`Keyring::add_epoch` exists; no
      UI). Needs a way to change the keyring and ACL without a drive-wide
      `write`, such as a server rule that `write` on a Conversation does not
      reach its SealedMessages.
- [ ] Group conversations from the UI (the model already supports them).
- [ ] Encrypted attachments.
- [ ] Notifications for new messages (needs the notifier, see
      `planning/notifications.md`).
- [ ] Conversations hosted on another server than the reader's.
- [ ] Report-by-reveal on the host.
- [ ] Local search over decrypted messages.
- [ ] Flutter client.
