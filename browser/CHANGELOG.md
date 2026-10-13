# Changelog

This changelog covers all five packages, as they are (for now) updated as a whole

## UNRELEASED

## [v0.41.0-beta.8] - 2026-10-10

- Phones: the chat view no longer scrolls sideways by a few pixels, the "more" menu no longer opens the on-screen keyboard, and the Back button closes an open dropdown menu.
- Schemas (#2151): `ensureOntology` creates or updates an ontology with content-addressed properties, classes and class constraints, and running it twice writes nothing; `ensureSchema` is now a deprecated alias. `ontologyFromJsonSchema` and `ontologyToJsonSchema` convert JSON Schema draft 2020-12 to and from that input. New: `propertyId`, `getEffectiveConstraint`, `setClassConstraint`, `useEffectiveConstraint`, `ensureLens`, `loadLenses`, and `store.newResource({ contentAddressedProperty: true })`.
- `ad-generate ontology push | lock | check` writes the same lockfile as `atomic-cli schema` (#2151).
- Tables, kanban, the ontology editor and forms store select options, single pick, limits and linked classes on the class instead of on the Property; each property in a class card has a Constraints section. Renaming a property's shortname or changing its datatype creates a new property and a lens that keeps old values visible (#2151).
- AI assistant: `find_schema` returns matching classes as JSON Schema (replaces `get_user_classes`), and `ensure_ontology` creates an ontology from a JSON Schema (#2151).

- Calendar: the repeat "Last day" date keeps focus while you type and is saved when you leave the field or press Enter, instead of after every keystroke (#2137).
- Documents: after mentioning a resource with `@` or the toolbar button, the caret sits in a paragraph after the card (one is added if needed), so typing no longer replaces the card (#2139).

- Forms: without a server the Summary tab says that summaries need a server, instead of suggesting to check the connection (#2119).
- Dashboard: a Count over no rows shows 0 instead of an em dash (#2111).

- Share dialog: the role for new invites (email field and Copy invite link) is a single-click Read / Write switch in the same style as the Public switch, instead of a Can write dropdown.
- Calendar: changing only the start or end time of a multi-day timed event keeps its end date (#2089).
- Tables: a JSON filter value is normalized (keys sorted, no whitespace) when you leave the field, so the exact text of a saved value matches its row (#2093).
- Invites: opening an invite link uses the server in the link instead of whichever server the browser had saved, so an invitee with a stale saved server no longer gets "Unrecognized token '<'". When the link points at a host that runs no server, a plain message says so. Creating a link for a drive whose server runs no node fails up front.
- Tables: a computed duration reads a date-only start as local midnight, like a local date-and-time, so it no longer differs by the timezone offset (#2083).
- Tables: clearing a Localized Text cell removes that language, so the fallback and the missing-translation marker come back (#2084).
- Calendar: the date filter explains that a repeating entry is matched on its first date (#2087).
- Cards: a record embedded in a document shows property names instead of slugs, hides created-at, drive and sort-order, and no longer shows an empty description line (#2081).
- Tables: hiding a column no longer hides its active filter chip, so a filter that still excludes rows stays visible and removable.

- New package `@tomic/mcp`: lets Claude Code, Claude Desktop, Cursor and other
  MCP clients that run a local process read and edit your Atomic Data. It is a
  small stdio bridge to your node's own `/mcp` endpoint, which is the one
  implementation of the tools (see the server changelog). `atomic-mcp connect`
  signs in with OAuth (PKCE, a loopback redirect): the approval page in the app
  asks which drives it may reach and whether it may edit, so your own secret is
  never shared, and the token is kept in a file only you can read. Account
  settings lists connected apps under **Connected apps**, with Revoke.
- Apps with a key of their own can still connect without OAuth through
  `/app/connect-agent`: `connectAgentUrl` builds the link (optionally asking for
  edit rights or specific resources), `waitForGrant` waits for Allow, and
  `publishAgentName` sets the name the person sees. The grants are the ACLs
  themselves (`grantAgent`, `grantsTo`, `revokeAgent` in `@tomic/lib`).
  `@tomic/lib/node` has `loadOrCreateLocalAgent` for the key file. `@tomic/cli`
  gets `ad-generate connect`, so private ontologies no longer need an agent
  secret in `atomic.config.json`.
- `@tomic/lib` now also exports the data verbs behind the in-app assistant
  (`readResourceCompact`, `queryResources`, `textSearch`, `semanticSearch`,
  `listDriveClasses`, `setResourceProperty`, `createResourceFromCompact`), plus
  the compact JSON-AD helpers (`toCompact`, `fromCompact`, ...) and short subject
  refs (`shortenSubject`, `expandSubject`) that used to live in the data-browser.

- Forms (beta): build a form or survey and share a link; guests fill it in
  without an account and each answer becomes a table row. Create one with
  New > Form, or from a table with "Create form from this table" (pick its
  columns). The builder has 21 question types, pages, drag-to-reorder,
  "Show when" rules that hide questions and pages based on earlier answers,
  required fields and limits, a Results tab (the table) and a Summary tab
  (charts). Settings cover public or invite-only access, an open/close
  schedule, a thank-you message, appearance and custom CSS. Share with a
  link, QR code or embed snippet. Guests get a small separate app
  (`@tomic/form-app`, built on the new `@tomic/form-renderer`) with a
  progress bar and answers saved on their device until they submit.
  [#875](https://github.com/ontola/atomic-server/issues/875)
- Forms: share links use the server that hosts the workspace. Without one, the
  builder says forms need a server instead of offering a link guests cannot open.
- `@tomic/lib`: the forms ontology (`forms`) is exported and, like
  `notifications`, fetched from the host rather than atomicdata.dev.
- Fix: after the server refuses a commit that depends on ops it never
  received, the next save resends the whole history instead of dropping the
  edit.
- Fix: uploaded SVG files display in the data browser.

- The per-group summary under a table has column headings, such as "Sum of Plus ones" and "Rows", so a bare number says what it measures.
- Tables: deleting a row you typed in the same session no longer shows its
  neighbour twice until you reload.
- Sidebar: notifications and sync have their own icon buttons next to Settings
  (they stay in the account menu too), in the same muted color as the menu's
  items, with an unread dot on the bell. The dividers in the menu are gone.
- Share: names under "People with access" open that person's profile.
- Error toasts: long subject URLs are shortened in the message. Copy still
  copies the full text.
- Tables: right-click a row's number to get the same menu as right-clicking one
  of its cells. Select several cells with shift+click or by dragging and
  right-click them for a menu that acts on all of them: clear the values, set
  one value in all of them, or delete the rows they touch. Delete is one undo
  step.
- Tables: drag a view's tab to change the order of the views.
- Tables: tick rows to delete several at once. Hover a row's number (or look
  left of it on a touch screen) for a checkbox. Once one row is ticked every
  row shows its checkbox, and the toolbar next to the filter button shows how
  many are ticked with a delete button. Undo brings all of them back at once.

- Signing in with an account whose identity is stored under the older `atomic:agent:` spelling no longer fails to keep the previous identity on this device ("no stored key for ..."). The same agent is now recognised in either spelling.
- A link or mention that points at a table View now opens the table with that view selected, instead of the view's configuration.
- A Number column's total or average no longer shows a small nonzero value as 0, and a Number filter typed as `2.5e-5` or with trailing zeros finds the same rows as the plain number.
- The shared sign-in card no longer says "This browser does not support passkeys".
  Where a passkey cannot work it shows no passkey option at all, and the
  portal and the app now decide that the same way.
- Apps can use Atomic's own UI through `store.ui`: a confirm dialog, a toast, a
  menu at the click, the resource menu, the share dialog and opening a
  resource. Atomic draws them, names the app that asked, and a menu is no
  longer cut off at the app's edge. Ctrl/Cmd shortcuts and Escape that an app
  does not handle now reach Atomic, so search still opens while you are in one.
- Apps can also let the person pick a resource or a file (uploading one if
  they like), and open Atomic's own form for a new resource of a class.
- Plugin views and apps now share one API: `store` from `@tomic/plugin` works
  like `@tomic/lib`'s Store (`getResource`, `resource.set`, `save`,
  `newResource`, `query`, `search`, `subscribe`) and drive apps get the same
  object. Packaged plugin views get `store.ui` too. `query` takes `filters`,
  `sortBy`, `sortDesc`, `pageSize` and `page`. `RPCClient` keeps working but
  is deprecated.
- Plugin views and apps can make several writes as one change with
  `store.apply(intents)`, in the same intent format a plugin's `run()`
  returns. Everything is checked before anything is written, a failed write
  rolls back the ones before it, and `store.undo()` reverts the latest change.
- A plugin can declare the `edit-schema` capability so its view may change
  the classes and properties of what it shows without asking each time.
- The More menu has two new actions, "Reload resource" (fetches the resource you
  are viewing from the server again) and "Restart app" (reloads the whole app).
  They and the "Go to" items (settings, drives, feedback) no longer clutter the
  list: type in the menu's filter to find them.
- Someone given a chat, or anything else, out of a drive they can't open sees
  all of it. A list answered from the local database was trusted whenever it
  was non-empty, but only a drive synced to this device has its whole list
  there: the guest's own messages and the ones present when they joined were
  shown as the entire chat, and a reload asked the same database again. For a
  drive this device hasn't synced the server is now asked once per list per
  session, and anything only the local database knows (a write not yet
  confirmed) is kept.
- Things shared with you out of someone else's drive update live and notify
  you. The app only listened to the drive you had open, so a guest in a shared
  chat never received new messages from the host, and got no notifications for
  them. Everything in "Shared with me" is now subscribed for as long as the app
  runs (`Store.subscribeLive`).
- Presence works in things shared out of someone else's drive. Presence was a
  channel per drive, which a guest given one chat can't read: the server
  refused them, so host and guest never saw each other there, nor who was
  typing. A view now also announces in the channel of the shared resource it
  is in (`Store.presenceScope`: the nearest resource with its own `read`
  list), and leaves the drive channel alone when it can't read the drive. One
  tab is one session across channels (`Store.presenceSessionId`), so nobody
  shows up twice.
- Signed in to a hosted account, the app now links its identity to that
  account (`/api/agent-link`), once per session and only after the identity
  check has settled on it. Services that only ever see a signature, like the
  integration proxy, can then tell which account a request is for, also when
  the account has no drive or paid plan. An account service without agent
  links, an email that was never confirmed, or an identity linked to another
  account are left alone. Builds that know no account service make no
  requests for it.
- Messages: send someone a direct message that only the two of you can
  read. Pick "Message" on anyone's avatar, or start one from the new Messages
  section in the sidebar with their Atomic ID. The server that holds the
  conversation stores it encrypted. It can see who talks to whom and when,
  not what is said. Someone who has never opened the app since this release
  has no key yet, and the app says so.
- `@tomic/lib`: the `conversations` ontology, and `Store.subscribeLive` to
  keep a resource outside the open drive live.

- Notifications are less noisy. The Notifications page shows one row per
  conversation ("Sanne and Polle: 3 new messages in Team chat") with names and
  titles as they are now, in your language. Coming back to the window while
  already on the conversation reads what arrived while you were away, and after
  you missed something the app offers system notifications once, instead of
  only a checkbox in Settings.
- The Notifications page shows placeholder rows while it loads, instead of a
  blank page that could flash "Nothing yet" before the list arrived.
- An app asking to use one of your accounts (Google Calendar, Clockify and so
  on) now asks in a dialog instead of a bar above the app, in plainer words:
  which app, which account, and that you approve it on the next page, on the
  integration proxy's site. If you already connected that account, the dialog
  lists it with when it was connected and which apps use it, and "Use this
  account" gives it to the app without leaving the page. A failure stays in
  the dialog so you can try again; the app hears `cancelled` if you close it.
  Tests that looked for the `Connect an account` group should look for the
  dialog named `Connect <platform>`; "Use existing connection" is now "Use
  this account".

- Signing in to a hosted account can now be enough to open your identity on a
  new device (#277). When the account service offers assisted recovery
  (`assisted_recovery` in `GET /api/auth/providers`), a new account's backup is
  wrapped by the account alone, so onboarding asks for no passkey and shows no
  recovery code, and the sign-in and restore steps unlock it by themselves
  after a recent sign-in. Existing backups get the extra wrapper the next time
  a passkey or recovery code opens them. The sign-in and restore steps now
  offer the same account options as the portal's sign-in page (Google when
  configured, passkey, email link), from one shared `AccountSignIn` component
  in `@tomic/service-ui`. Builds that know no account service (the FOSS
  release, self-hosted nodes) show none of it and make no requests for it.
  Account recovery has a "Let Atomic help me recover" switch: off removes the
  assisted wrapper, so only a passkey or recovery code opens the identity. A
  wrapper records which service key made it (`kdf_params.key_id`); after the
  service rotates its key, the next unlock re-wraps with the new one. Accounts
  may now have an `acct_` id apart from their address: backups and bindings
  keep using the id, and the app shows `address` from `GET /api/me`.

- Agents, Skills and MCP servers are edited in a dialog again. Their lists stay
  on the AI settings page, but creating or editing one opens a dialog with the
  form and Cancel / Save buttons, instead of swapping the list for the form
  inside the settings section. Save stays disabled until the required fields
  are filled in.
- The sidebar's App panel is gone. Its entries (your user page, Notifications,
  Integrations, Sync, Feedback, About and Install App) now live in a dropdown
  that opens from the user row at the bottom of the sidebar, with Settings as a
  gear button beside it. A dot on the row shows unread notifications.

- The role picker next to the email field in the share dialog opens again. A
  click on it also focused the email field, which closed its option list right
  after it opened. The email field also asks password managers (Bitwarden,
  1Password, LastPass, Dashlane) not to fill it, since it holds other people's
  addresses.
- Images in documents show again instead of "Failed to load image". An uploaded
  image's address points at the server, but a browser-only workspace never
  sends its files there, so the server could not answer it. The editor now shows
  the copy this browser already holds, as file previews already did, and falls
  back to the server when there is none. New `useBlobObjectUrl` hook in
  `@tomic/react` and `blobSubjectFromDownloadUrl` in `@tomic/lib`.

- The "Could not set up your account passkey" message now also names the request that failed and its HTTP status, so a report says whether the session, the challenge or the credential was refused.
- The "Demo setup stalled" report now says where the time went. It carries how
  long each setup step took and whether the tab was in the background, and a
  demo that does finish after the notice sends a second, informational report
  with its total time. The notice fires at a fixed 45 seconds, so until now a
  slow machine and a stuck one looked the same in Sentry (`ATOMIC-BROWSER-1J`).
- Settings → Integrations: the proxy and plugin catalog URL fields only show
  a Save button below them. Resetting to the default is now a small Reset
  button at the end of the field, shown only while the value differs from the
  default.

- Pasting an agent secret that opens a different agent than the signed-in
  account no longer signs that account out on its own. The app now says which
  account is signed in, shows both agents, and lets the user stay signed in or
  use the secret and sign out.

- Starting the demo is one calm screen. From "Try Atomic" to the workspace
  the page shows only the orbiting mark from atomic.place, instead of a blank
  page, a "Checking local storage…" card and a "Setting up your demo…"
  spinner in turn. The workspace fades in once its welcome document has
  content, and the scripted teammates wait a moment before they start.
  Setup is also faster: the database's WebAssembly is fetched and compiled
  once, from the first line of the page, instead of up to twice after the app
  loaded; the demo opens only the guest's database; and it no longer waits for
  an account check it does not need.
- A second tab no longer leaves the local database locked. When a tab takes
  over the database from a tab that stopped answering (in Firefox, a throttled
  background tab), the old tab now closes its worker and carries on through the
  new one. It used to keep the file open, so the new tab failed with
  "OPFS unavailable: … NoModificationAllowedError" and ran without its local
  cache, and anything needing that cache, such as creating a drive, failed with
  "Open this drive with local storage available before disconnecting". Firefox's
  locked-file error now reads as one plain sentence, and those actions name the
  database's own reason instead of a disconnect the reader never started.
- Turning workspace sync off says what is actually in the way. All three of its
  preconditions used to answer with "Open this drive with local storage
  available before disconnecting", so someone signed out, or on a server this
  client holds no live connection to, was told to do something they had already
  done. Each one now names itself, and a socket that exists but is not open says
  so rather than leaving the attempt to fail on "WebSocket is not open". The
  local database is also waited for instead of refused: it attaches a few
  hundred milliseconds after a page load and again after every sign-in, and a
  click inside that window was rejected outright.
- A local-only workspace is recognised whatever spelling its subject is written
  in. The set of disconnected workspaces is read through the canonical form but
  was written raw, so a trailing slash or a legacy `did:ad:` identifier could
  store a key nothing found again, and a resource inside such a workspace could
  still try to reach the server.
- One Loro wasm panic no longer turns into an error every few seconds for the
  rest of a tab's life. Presence gives up the drive's ephemeral store on the
  first failed call, whichever call it is, including a peer's bytes and the
  read behind the peer list, and it now stops Loro's own expiry timer while
  doing so. That timer lives in Loro's JavaScript wrapper and keeps calling
  into the abandoned store, which is how a single panic anywhere in the shared
  wasm module produced a long stream of unhandled `RuntimeError: unreachable`
  reports from `setInterval`.
- Notifications while the app is open, on the web and in the desktop and
  Android apps: new chat messages, comments on things you made and replies to
  you show as a toast, or as a system notification when you're in another tab,
  window or app. Nothing shows for the conversation you're already looking
  at. System notifications are switched per device under Settings →
  Notifications. The desktop and Android apps get them through
  `tauri-plugin-notification`.

- Notifications page and Inbox: every notification is kept in an Inbox in
  your private drive, so it's there on all your devices. The sidebar shows
  Notifications with an unread count; the page lists them newest first, and
  opening one (or the conversation it's about) marks it read.

- Android app: the back button closes an open sidebar drawer or dialog
  instead of navigating away underneath it. With nothing open, back works as
  before (previous page, then leave the app).

- Fix: a table no longer goes to an error screen while one of its columns is
  still loading. A resource-array cell reads its own property from the store to
  decide between the select and relation pickers, and asked for that property's
  form category before the resource had arrived. A property with no datatype
  yet threw "Unknown datatype: undefined", which reached the page's error
  boundary and replaced the whole table. An absent datatype now means "no
  category yet", the cell renders as a relation until the property lands, and a
  datatype that is present but unrecognised still throws, since that is a real
  gap rather than a slow fetch.

- `@tomic/lib`: `store.createSubject()` and `store.isAliased()` are deprecated
  (they still work). The app no longer creates temporary `_new:` subjects
  that are renamed on first save: the new-resource form, new-resource dialogs
  and new table rows all create their resource with `store.newResource()`, so
  it has its final subject from the start. Use `store.newResource()` (with
  `deferGenesis: true` for a draft that is filled in before its first save)
  and read `resource.subject`. `_new:` subjects written by older builds are
  still read and synced as before.

- `@tomic/lib` answers a stale drive-sync probe (`SYNC_RESEND`) with the full
  version-vector `SYNC` instead of a range-based set reconciliation over
  `RBSR_FP` / `RBSR_ITEMS`. The range descent cost the server more than the
  full exchange. `rbsr.ts` is gone, and `WSClient.rbsrItems` is
  now `WSClient.driveInventory`.

- A workspace a Cloud Server node refuses ("not enrolled") no longer sits on
  "Connecting…" with changes pending forever. The server card says the server
  doesn't host it, and "Sync this workspace with this server" can be turned
  off even though the server won't answer, keeping it on this device. A
  suspended Cloud Server enrollment no longer counts as hosted, so the app
  stops pointing a drive at a node that will refuse it.
- Fixed opening the app while signed in to atomic.place sending you to sign
  in again, and signing in with your secret then signing you out of
  atomic.place. A backup saved before the `did:ad:` → `atomic:` rename names
  your agent in the old spelling, and the check that compares it with the
  agent on this device compared the text, so one agent looked like two. The
  gate then switched identities, and the secret sign-in ended the account
  session as if the secret belonged to someone else.
- Fixed a drive restored from Cloud Vault on a new device showing its raw
  identifier as its title, or being replaced by an empty new workspace. The
  app kept the answer it had before the restore ("not found") and trusted it
  over the data the restore had just written, so sign-in could decide there
  was nothing and create a new home over the restored one.
- A private workspace the app has to recreate is titled after whoever it
  belongs to, like the one onboarding and an accepted invitation already
  make. A returning account on a second device, and a sign-in whose cloud
  restore did not finish in time, used to land in a workspace called "My
  drive" moments after proving who they are, which reads like the wrong
  account. An account with no name set still gets the default.
- Fixed a private workspace being titled `[i18n-404:1664]`. That title is
  written when the workspace is made, so it stayed. The app composed it from
  the translation catalog while still starting up, and the catalog is not
  always loaded by then; the default is a plain string again, and the name
  beside it is deliberately kept out of the catalog for the same reason.
- The Share dialog is one screen: invite people, see who has access and change
  their role (Can write, Can read, Remove access), see who gets in through a
  parent folder, and set public access to Off, Read or Write. On hosted Atomic
  you can type email addresses and an optional message and the invite link is
  emailed to them; on a self-hosted server the invite link, with its role, is
  what you copy and send yourself. The title shows the resource's name.

- Fix: a presence announcement carrying something Loro cannot store no longer
  breaks the tab. A view's presence payload is typed as whatever that view
  likes, so a callback or a class with methods can travel in it, and Loro
  answers such a value by panicking rather than erroring: in a browser that
  arrives as a bare `RuntimeError: unreachable`, and the wasm module is unusable
  afterwards (a cyclic object corrupts its heap instead). Because the entry is
  retained and re-sent every ten seconds by the presence heartbeat, storing one
  turned into an unhandled error on a timer for as long as the tab stayed open.
  Announcements are now checked before they reach Loro, a refused one names the
  offending field in the console and leaves the last good entry in place, and a
  broadcast that fails anyway stops the heartbeat instead of repeating itself.

- Documents and meetings show a formatting toolbar above the text (block type,
  bold, italic, strikethrough, quote, code, link, lists, image and mention), so
  new users don't have to know the `/` and `@` commands. It can be hidden, which
  the browser remembers, and brought back with the small button in its place.
- Fix: editing a kanban card's title is reliable. A space or Enter typed in
  the title started a keyboard drag of the card, which swallowed the space,
  moved focus away and saved a partial title; selecting text with the mouse
  could start a drag too. The editor also had a different size than the title,
  so the card resized when editing started and the next click could land on
  another card and open it. The editor now matches the title's box and wraps
  like it, opens with the caret under the click, commits on Enter or blur,
  cancels on Escape, and shows the new title while it saves.
- AI chat options and the speech settings let you pick the microphone used for
  voice messages. The agent select in AI chat options is clickable over its
  whole width again: an inline width left its chevron outside the select.
- Fix: someone who signs up from an invitation and has no recovery backup can
  still accept it. The portal opens the restore step for an invitee whenever it
  cannot rule out an earlier identity, and with nothing to restore that step
  stopped at "No recovery backup was found". It now offers to create the
  account, keeping the invitation.
- Typing `@` in a document lists recently opened resources in that drive, topped up with the drive's own children, instead of "No results found".
- The sidebar's New button stands out for first-time users. It opens the page
  for everything you can build (apps, websites, tables, templates), but at rest
  it is a faint grey line under the tree. Until the New page has been opened
  once in this browser, it shows in the accent colour on a soft tint and pulses
  a few times after 20 seconds.
- Fix: a task added from a table's calendar, grid, quick-add button or paste
  now starts in the board's Todo lane instead of "No status". Tables carry
  `table-row-defaults` (property to starting value), which every way of adding
  a row fills in for what it does not set itself. Templates set it (Todo, Lead,
  Wishlist, Want to read, Invited), as does a Status column the board creates,
  and any board lane can be made the default from its header menu.
- Fix: a table breakdown's "n rows" counts every row in the group. It showed
  how many rows fed the first statistic, so Project tasks, which sums Estimate,
  read "0 rows" under each status until tasks had an estimate. And a select
  option's page counts the rows that use it through its column (a task's
  Status), not only through `tags`, so Doing no longer reads "0 resources".
- Move the Connections and Automations buttons above table views into the table's context menu, next to Export to CSV. They open the same dialog as before.

- App frames call the integration proxy directly, with a capability instead of a relay (ontola/atomic-plugins#54; replaces #1657's `proxy` relay and LocalThought's rotating connection codes, which the new proxy no longer issues). A frame makes its own non-extractable Ed25519 key in memory; the page checks that the connection is delegated to the app and signs a capability bound to that key (`integration-proxy-capability-v2`, 10 minutes); each request is signed by the frame key with a version 2 request signature. `store.proxy.request(...)` keeps its shape; it mints a new capability shortly before expiry and once more on a `capability_expired` refusal. View op `proxy` is gone, `proxyCapability` is new. Connecting no longer logs in at the proxy: the page redeems the handoff signed with the user key, which makes the user the connection's owner, then delegates it to the app (also signed). The connect bar offers an existing connection for the same platform, which only adds a delegation. Only apps with their own agent (made with `createApp`) can be given a connection for now; others are told so. Where WebCrypto has no Ed25519 the frame fails with a message saying so. Existing connections are not migrated: connect again.
- `@tomic/lib`: `signRequest(url, agent, headers, { method, body })` makes a version 2 request signature (ontola/atomic-plugins#54), which also covers the method and the SHA-256 of the body and sends `x-atomic-signature-version: 2`. Without `method` it signs version 1 as before, and a string fourth argument is still the legacy subject. New exports `requestSignatureMessageV2`, `sha256Hex` and `SIGNATURE_VERSION_HEADER`. `Agent.generateNonExtractable()` makes an agent whose Ed25519 key is a non-extractable WebCrypto key, with subject `atomic:agent:<public key>`; where WebCrypto has no Ed25519 it throws instead of falling back to an extractable key.
- Plugins moved to [atomic-plugins](https://github.com/ontola/atomic-plugins). The Integrations page lists what that catalog publishes (`catalog.json`, fetched at runtime; the URL is configurable under Settings > Integration) instead of plugins compiled into the app and server. The bundled GitHub issues, Notion, Pets, MT940/camt.053, Clockify and Google Calendar (Devonian) integrations, the `devonian` dependency and the `/app/devonian-demo` page are removed. The Todoist lens and the Moneybird administration picker are removed too. LocalThought connect and sync, and the "Show API plugins" toggle, are removed from the app: plugins will run in their own iframe and make proxy calls through the host.
- Tracker tables get an Issues view: open and closed issues split by the status column (or a boolean column), filtering by title or `#number`, New issue, and Close/Reopen per row. The Issue Tracker template opens it as a tab.
- Columns whose property has no name are labelled from its shortname, capitalised and with dashes shown as spaces, in the table heading, filter bar, property toggle and summary bar. A name someone typed is still shown exactly as written.
- An import that stops early (for example at the 5,000-record cap) keeps what it fetched and shows "Synced with issues" instead of failing outright.
- A plugin run that proposes no changes shows only Close, instead of a disabled "Apply 0 changes" button.
- Fix: the integration proxy may live on a `.localhost` name. `proxyOrigin`
  allowed plain http only for the bare `localhost` and `127.0.0.1`, so a proxy
  at, say, `http://atomic.localhost:19090` was rejected, and because the value
  is read during render that rejection replaced any page showing integrations,
  the settings page included, with "Error loading resource". RFC 6761 gives the
  whole `.localhost` TLD to loopback and browsers treat those names as secure
  origins, so they are accepted now, `[::1]` with them.

- Improve AI chat on phones: use the full screen width, keep the composer above the keyboard and the final response line visible as it opens, remove the bottom spacer, reduce padding, use the full message width, add the chat resource menu to its header, and move model selection and token usage into Chat options. Remove generated follow-up suggestions and rename Atomic Assistant to AI chat ([#1591](https://github.com/ontola/atomic-server/issues/1591)).

- Fix: someone joining a drive through a browser invitation is told when the
  pairing is not getting anywhere. The page showed "Connecting…" and "Waiting
  for a peer" indefinitely: `WebRtcPeer`'s 60 second pairing timeout only
  exists on a peer that has built an `RTCPeerConnection`, and the guest is the
  one waiting for an offer, so it had no timer at all. After 60 seconds without
  a peer the page now says so and points at what the inviter has to do. The
  attempt keeps running, so a slow pairing that later succeeds still does.
- Fix: the editor's slash menu no longer reaches through an unmounted renderer.
  `onStart` positions the menu again on the next animation frame, which can
  land after the suggestion was destroyed.

- Fix: someone who opens a chatroom shared from another drive sees the messages
  in it. The message list is a collection query, and a collection defaults its
  drive scope to the viewer's active drive. A guest arriving through an invite
  has their own drive selected, so the query went looking on the wrong drive and
  answered with nothing, leaving "No messages yet" on a thread that had them.
  The query now scopes to the drive the thread itself is stamped with, which
  for a shared thread is the owner's. The same hook backs the comments panel
  and the meeting chat, so those are fixed with it. Scoping to the thread's
  subject instead, as this first did, fixed the guest's first read but broke
  every later one: the local index is keyed by drive, a subject is not a key
  in it, and the panel then stopped showing messages other people sent while
  it was open.

- Identifiers are now emitted as `atomic:` (`atomic:{genesis}`,
  `atomic:agent:`, `atomic:commit:`, `atomic:blob:`, `atomic:node:`).
  `did:ad:` is accepted forever and names the same resource. Pairing is
  `atomic:node:{id}?v=1&drives=*`; a node identifier starts pairing,
  anything else navigates. The store canonicalizes at `normalizeSubject`.
  Fetch uses `/resource?subject=` (`/atomic` and `/did` are aliases).
  Sync lists the `canonical-scheme` capability and sends `did:ad:` to a
  server that does not advertise it. Blob copy, identity mint, and node
  pairing accept both spellings (#1584).

- Fix: installing a plugin works again. Since the `Installation` class started
  requiring `release`, the server refused the commit that creates one with
  "Property .../properties/release missing", the outbox dropped it as terminal
  and nothing was installed; both the integration store and a zip upload go
  through `installRelease`, so neither worked. `store.newResource` signs the
  genesis commit from the propvals it is handed and holds it until `save()`,
  so a property set between those two calls is missing from the commit the
  server validates. `release` is now one of the propvals.

- Fix: opening an AI chat no longer risks taking the page to its error
  boundary. `useEditor` replaces the tiptap editor when its dependencies change
  and destroys the old one, which nulls its `commandManager` while its last
  state stays readable, so `isEmpty` still answers and `commands` throws
  ("Cannot read properties of null (reading 'commands')"). A prefill arriving
  in that same breath is what "New automation" and "AI edit" do. Both effects
  now check `isDestroyed`, and a prefill that is skipped is re-applied to the
  editor that replaces it.

- Fix: the authentication cookie is refreshed before the proof inside it
  expires. `setCookieAuthentication` signed a proof once and stored it for a
  day, and `checkAuthenticationCookie` only asked whether a cookie existed, so
  a browser went on presenting the same proof for as long as the tab stayed
  open. Since the server started refusing a proof older than five minutes, that
  meant cookie-authenticated requests failed five minutes into every session,
  with nothing re-signing. The cookie now lives no longer than the proof it
  carries (`AUTH_PROOF_MAX_AGE_MS`), and the freshness check reads the signed
  timestamp out of the cookie and reports an ageing proof as absent
  (`AUTH_PROOF_REFRESH_MS`), which is what makes the request path install a
  fresh one.

- The data-browser no longer reports to Sentry from a dev server. Vite's hot
  reload legitimately throws while swapping modules ("\_s is not a function",
  "Cannot access X before initialization", all with `@react-refresh` frames),
  which is not a defect in anything shipped, and those arrived rated above
  every real bug in the backlog. `initSentry` returns early when the resolved
  environment is `development`; setting `VITE_SENTRY_ENVIRONMENT` still reports
  from a local build on purpose.

- Perf: creating a plugin on a drive that has no plugin schema yet no longer waits for nineteen round trips. `ensureSchema` writes the sixteen properties and three classes of `pluginSchema()` with one save each, and `ensureAll` awaited them one after another, which is most of the time between clicking "New plugin" and the page appearing, and enough to time the e2e suite out. The terms are independent resources under the same ontology and none reads another's subject, so the creates now go out together; the ontology's own list is still assembled in spec order.
- Fix: deleting a resource no longer leaves a "Resource with error" row in the sidebar. A `parent=` query keeps answering with a destroyed child for a moment (the answer was computed before the destroy landed, and `Collection.fetchPage` races the local index against the server's `/query`), and every reader that had not itself witnessed the delete put the row back — which is not cosmetic, because rendering the row asks the store for the resource and re-creates the entry the destroy removed. "This subject is destroyed" is now one fact on the `Store` (`isDestroyed` / `clearDestroyed`, the in-memory half of the tombstone `removeResource` already wrote to the local database) instead of a suppression set per reader: `Collection._removedSubjects` and `useChildren`'s `removedRef` are gone, and both read the store. A destroyed subject is never a member of a collection, incoming state for one is refused after the server ack as well as before it, and `getResourceLoading` answers for one from the tombstone instead of firing a request that can only 404. Only creating a resource again under the same subject lifts a tombstone; a stale answer no longer can.
- Toasts no longer cover the navbar's buttons when the navbar is at the bottom: the toast container is lifted by the navbar's height, so the sidebar toggle, search and context menu stay tappable while a toast is up. The sidebar's 3.8rem `OverlapSpacer`, beneath the App panel, is gone: it dated from the floating-navbar mode and guarded an overlap that cannot happen, since the sidebar's height already excludes the navbar ([#1565](https://github.com/ontola/atomic-server/issues/1565)).
- The navbar sits at the bottom by default on phones and tablets, so the sidebar toggle, the search button and the context menu stay within thumb reach. The signal is a touch-primary pointer rather than viewport width, so a landscape tablet also gets the bottom bar and a narrow desktop window does not. Desktop keeps the top bar, and a position picked in Settings is untouched ([#1565](https://github.com/ontola/atomic-server/issues/1565)).
- Fix: a local database that cannot be decrypted is no longer deleted on sight. `openClientDb` discards and recreates an undecryptable OPFS file only when the caller passes the new `discardUndecryptable`, and the data-browser passes it only when no wrapped key record exists for that agent — i.e. when the key is genuinely unrecoverable rather than merely absent from this page load. The old behaviour was unconditional, on the reasoning that the file is a cache whose contents are re-fetchable from the server; that is false for a local-only drive, whose only copy it is. Relatedly, `resolveDbKey` no longer invents a fresh key when an agent has a wrapped key record but no session key (an agent restored from a non-extractable keypair, where no secret enters JS). It returns null and no worker is started, so the store runs server-only until a sign-in with the agent secret or recovery code unwraps the real key — which is what the code's own comment already claimed it did. Minting a key in that state produced exactly the wrong-key open that triggered the delete, so a drive that existed only in the browser could be destroyed with no user action, while its key was still sitting in IndexedDB waiting to be unwrapped. New `discardUndecryptable` option on `ClientDbOptions` and the worker's `init` message, defaulting to off.
- Fix: `agentVaultProof` verifies that a live signature reproduces itself unless the signer positively declares itself deterministic. It used to double-check only signers that declared `signsDeterministically: false`, so one that said nothing was taken on trust — and a signer that randomizes (WebKit's WebCrypto does, for Ed25519) could have had a non-reproducible signature turned into the key its Cloud Vault backups are wrapped under.
- Fix: `@tomic/lib` writes the Loro `datatypes` tags in the export path shared by genesis and drain-time signing, after the user's pending ops are sealed into their own commit. The drain used to tag first, which folded a `set()` edit into the tag write's `atomic:system` commit — the canvas undo stack skips that origin, so the first edit of a `json`/reference property after a save could not be undone.
- Perf: a cold page load asks the local database (OPFS worker) for all the resources a render pass mounts in one round trip instead of one per `useResource`. `Store` coalesces the render-phase cache misses of a tick into a single `getResourcesWithSnapshots` call (chunked at 200 subjects), and a subject asked for twice while a read is pending or in flight shares that read. 50 mounted resources went from 50 worker messages to 1; the tri-state answer (`true` / `false` / no database to ask) and the "ask again once the database attaches" behaviour are unchanged.
- Fix: deleting a resource while offline no longer loses the delete. `Resource.destroy()` now goes through the durable `LocalOutbox` like every other write: the signed destroy commit is queued (`OutboxEntry.signedDestroy`, persisted in localStorage), the resource is removed locally at once, and the drain POSTs the envelope with the usual backoff and reconnect replay. Online, `await destroy()` still resolves after the server acknowledgement and rejects on a real refusal; offline it resolves with the delete queued. A resource created and deleted before either write reached the server is dropped without a POST, and a server answer that the resource is already gone counts as acknowledged instead of retrying forever. While a delete is queued, incoming state for that subject (a subscription push, a fetch that raced the delete, a stale OPFS row) no longer resurrects it. `Store.hasPendingDestroy(subject)` is new; `LocalOutbox` gains `setDestroyCommit`, `clearDestroy` and `discard`.
- Fix: the outbox decides whether a refused commit is terminal (drop it), benign (drop it quietly) or blocking (park it) from the server's structured error code first — the `ERROR` frame's `code` over WebSocket, or the `errorCode` property on the HTTP `/commit` error body — and only falls back to matching message text when the response carries no recognized code (older servers). Previously the store's "benign drop" check (`is_genesis: true, but the resource already exists`, `Commits cannot be edited`) matched message text only, so a wording change on the server would have turned a silent bookkeeping drop into an error toast per commit, and "Commits cannot be edited" had no code at all. New `ErrorCode.IMMUTABLE_COMMIT` (10) and `isBenignTerminalCommitError(message, code)` in `@tomic/lib`.
- Local Thought connections install a folder after one access check and import in the browser without a preview dialog. Opening the folder or a table refreshes automatically, with five-minute refreshes while open, visible sync status, and local-edit preservation.
- Fix: form inputs validate before writing. `InputString` and `InputURI` no longer put an invalid value into the resource while showing an error; all inputs share one validate-then-set hook (`useValidatedInput`) and surface the datatype's actual error message (e.g. "Not an integer") instead of a generic "Invalid value". `ResourceField` now accepts and forwards `commit` / `commitDebounceInterval`, and every input honours `commitDebounceInterval` (Markdown, Number, Boolean, Date, Timestamp, Resource, ResourceArray and FilePicker previously fell back to the 100 ms default). A required field whose value loads after the first render is now flagged correctly.
- Fix: `Resource.remove()` and `Resource.push()` emit `LocalChange` like `set()` does, so `useValue` / `useArray` re-render when a field is cleared or an item is appended. `useValue`'s setter clears a previously reported validation error when called with `undefined`. `useArray`'s `push` saves through the same debounced scheduler and error handling (`handleValidationError` / `store.notifyError`) as `set`, instead of an immediate `resource.save()` that only logged failures. `StoreContext` no longer defaults to a phantom `Store`: `useStore()` throws when no `<StoreContext.Provider>` is mounted.
- `@tomic/lib`: one list of server-managed properties (`server-managed-props.ts`) replaces the three copies in `resource.ts` and `store.ts` that had drifted apart; the OPFS cold-load guard now also treats an inline `genesis` certificate as skeleton, not content. One serializer (`Resource.toClientDbJsonAd()`) writes the local-database row from both `Store.addResource` and `Resource.persistToClientDb`, and a durable save now records its write in the store's dedup stamp so the next ingress does not rewrite the same row.
- Comment on a table row, like in Notion. Every row's gutter carries a comment bubble: it shows up on hover for a row with nothing on it yet, and stays put — with the count, highlighted while unseen — for a row that has comments. Clicking it opens that row's thread in the Comments panel, headed by the row's title; another row's bubble switches threads, and the same row's closes the panel. A row is a resource of its own, so its thread is the ordinary one (Messages whose `about` points at the row) and needs no setup. The Comments panel can now be aimed at a resource inside the page rather than only at the page's own; the navbar button keeps opening the page's thread.
- Fix: the fork bar no longer fetches the server root on every resource page.
  It renders above every resource and only returns `null` for a non-fork after
  its hooks have run, so `useResource(originalSubject ?? '')` fired for all of
  them; an empty subject resolves against the page origin, which serves no
  resource (no Drive is created at `/`), so each page load spent a request on a
  404 and logged a console error. It asks for `unknownSubject` instead, which
  the store answers from memory without touching the network. This is what made
  the `offline-persistence` and `offline-tables` e2e specs fail: they assert on
  unexpected browser console errors, and with the WebSocket disconnected the
  miss surfaced over HTTP as a logged 404 rather than a silent protocol answer.
- The "All versions" link is gone from the version scroller. It pointed at the
  server's `/all-versions` endpoint, which rendered the same history the
  scroller was already showing, paginated and without attribution. Both
  endpoints behind it are removed.
- Fork bar: "Review changes" opens the per-property diff (the original's current value against the fork's) and names the properties the original also changed since the fork, so a reviewer sees what a merge writes over instead of a count.
- A dashboard is reachable from its table: "Add view" offers **Dashboard**, which creates an empty Dashboard as a child of the table and shows it as a tab (`view-kind: dashboard`, `view-dashboard`). Switching an existing tab to Dashboard does the same. The Dashboard stays a resource of its own, so a Drive page or a document can still embed it.
- Fix: creating a second table column with a name that already exists in the drive's ontology (e.g. two "Status" columns) no longer mints a colliding property shortname that silently corrupts the ontology. A compatible existing property is reused instead; an incompatible one gets a disambiguated shortname (`status-2`) ([#1504](https://github.com/ontola/atomic-server/issues/1504)).
- Verified the GitHub issues (devonian) plugin keeps issue open/closed state and Atomic kanban card status in sync in both directions, including dragging a card in the real kanban board; added regression coverage for reopening and for the native drag path ([#1505](https://github.com/ontola/atomic-server/issues/1505)).
- Stop restoring stale right-side panels across sessions, accounts and drives; close meeting/comments panels when their target disappears.
- Following indicator: a tight blue ring on the followed avatar in the navbar and sidebar, expanding to a "Following" chip on hover ([#1486](https://github.com/ontola/atomic-server/issues/1486)).

- Fix: file previews and avatars wait for the local blob lookup before requesting the server, avoiding transient 404s for offline uploads. `useFileObjectUrl` accepts an optional network fallback URL and returns `undefined` while the local lookup is pending.

- Fix: `@tomic/cli` `ad-generate ontologies` works with `did:ad:` ontology subjects. A DID is not an HTTP URL: the CLI needs `serverUrl` (the Atomic Server origin) and fetches `GET {serverUrl}/did?subject=…`. Pasting the address-bar form `https://host/did:ad:…` no longer fails with `Resource has wrong subject in @id` — that URL is an alias, and the resource's `@id` is the DID. `ad-generate init` writes `serverUrl`.
- Page transition animations are now **opt-in**. They still break outside Chromium on desktop (a card-to-page morph blows up into an overlay on Firefox and on Android Chrome), so they are off until every browser we support is verified ([#1563](https://github.com/ontola/atomic-server/issues/1563)). Settings > Accessibility gains "Enable page transition animations" in place of the old "Disable" checkbox, backed by a new `viewTransitionsEnabled` localStorage key (default `false`). The old `viewTransitionsDisabled` key is no longer read: reusing it would have left transitions on for anyone who had ever toggled the old checkbox back off. The transition machinery and CSS are untouched, so turning them back on is a default flip.
- Fix: page transitions on Firefox no longer smear into a giant overlay or get skipped entirely. Snapshot sizing is scoped by `view-transition-class` (titles keep the height-based aspect-ratio rule; card→page morphs fill the group), title links that wrap a heading are `inline-block` so Firefox does not treat them as duplicate names (IB splits), and a failed or hung `startViewTransition` still navigates and skips the overlay instead of covering the page.

## [v0.41.0-beta.7] - 2026-09-12

- Add template onboarding with editable previews and consistent mobile UI.
- Prevent Cloud Vault growth on refresh and download vault objects concurrently.
- Connect the selected hosted drive before falling back to vault restore during sign-in.
- Preserve editor selection during remote updates and improve focus, table selection and save-state feedback.
- Fix deleted sidebar items returning from stale queries.

- Add peer rooms for up to eight simultaneous browsers on the Sync page with WebRTC collaboration, OPFS reconciliation and attachment sync without a Cloud subscription. Discovery defaults to the shared managed signaling service, independent of the drive’s data node. Export `BrowserPeerSync`, `WebRtcPeer` and `WebRtcTransport` from `@tomic/lib` ([#1396](https://github.com/ontola/atomic-server/issues/1396)).
- Portal Open links select their workspace; ordinary resource links keep the current drive.
- Sync distinguishes remote node data from Cloud Server enrollment, explains drive-specific plans, and refreshes account/recovery status after portal sign-in.
- Account linking explains its purpose without implying another purchase or workspace transfer.

- Reconcile the selected cloud drive after switching drives or signing in on an open connection, so Sync no longer waits for a page refresh to confirm its status.

## [v0.41.0-beta.6] - 2026-09-09

- An older server response no longer rolls back the local cache after an edit, fixing dashboard configuration reverting on reload.

- Private plugin views load authenticated assets through the parent while retaining their sandbox.
- Idempotent offline saves no longer leave the sync queue retrying an empty update.
- Navigating to sign-in no longer fetches the welcome screen as a data resource.

- Account recovery: reveal the agent secret with a recovery code when passkey authentication is unavailable, and enroll an additional passkey.
- Desktop onboarding explains workspace discovery with a dedicated loading screen, offers discovered sources and a manual server address, and retries while waiting for another device.
- Sync and Cloud Server status now describe the selected drive; linking a cloud account does not imply that its workspace has been transferred.
- Cloud Vault backups preserve drive names and emoji, run incrementally, and retry transient failures.
- Security fixes bind managed account tokens to their portal and validate links and uploaded content.

- Right-clicking a resource (sidebar link, table cell, kanban card) opens the same searchable action menu as Cmd+M: the filter input is focused, typing narrows the actions, Enter runs one.
- Fix: `Store.applyIncoming` imports the echo of this client's own commit before deduping it, so the server's `lastCommit` stamp lands locally and a collaborator's next edit applies instead of triggering a catch-up fetch that remounted the editor.
- Fix: an own commit's echo is recognised by signature (registered at sign time), not only by the `lastCommit` the ack stamps, so an echo that lands before the ack no longer re-renders the page mid-edit (the tag picker in the tables e2e closed under load).
- Fix: ops that arrive from the server are folded into the Loro save cursor as they are imported, and an ack keeps them there. Without this the echo made the resource look dirty again after every save and the client re-committed an empty delta every 130 ms until reload.
- Fix: a pending edit that Loro has to seal early (an import, a snapshot export, a server response written into the doc) is committed under the token the next drain will use, so it stays in its own History version instead of collapsing into the base one.
- Fix: automatic Cloud Vault backups failed in the browser with "Cannot convert 1 to a BigInt" — the checkpoint number is a 64-bit integer on the WASM side and must be handed over as a BigInt.
- Fix: the recovery-code step of onboarding threw `_w_ctx_ is not defined` in the dev build (the i18n extractor emitted the nested-message form for one button label without its callback); the label is a script-scope string now.
- Cmd+Up (go to parent) works in tables again: ArrowUp no longer matches
  with Ctrl/Cmd held, and the parent action fetches the resource when a
  stub has not yet materialized `parent`.
- `useCollection` resets `ready` when the query changes, so the table
  grid's `aria-busy` stays true until the new page lands.

- Commits are signed envelopes: `CommitDetail` does not fetch `did:ad:commit:`
  resources; author and dates come from the resource. History no longer
  navigates to a commit DID, and the Sync page log no longer links commit ids.
  Sequential saves no longer set `previousCommit`.
- History shows who signed each version. `Store.getHistoryAttribution(subject)`
  merges the server's `GET /history-attribution` with the local ClientDb
  (`historyAttribution`), and `VersionTitle` labels a version
  `by <agent> Verified` (signature checked), `Unverified` (envelope present,
  signature failed) or `by peer … Unattributed` (no envelope covers it).
  `attributionForVersion`, `mergeHistoryAttributions`, `parseHistoryAttribution`
  and the `HistoryAttribution` / `Attribution` types are exported from `@tomic/lib`.
- [#1232](https://github.com/ontola/atomic-server/issues/1232) Unified
  actions: the ⌘K palette shows a capped Actions section for the current
  resource, hotkeys and the shortcuts overlay/page render from the action
  registry, and simple verbs (`delete`, `favorite`, `share`, `history`)
  derive in-app AI tools.

## [v0.41.0-beta.5] - 2026-09-04

- `@tomic/lib`: `Store.search` uses the durable WASM/OPFS inverted index
  (`ClientDb.search`) for local hits, including `filters`. The MiniSearch
  in-memory index is removed. Online searches merge with hosted `/search`
  (same KV engine). Offline without ClientDb returns no local hits.
  `ClientDbWorker.search` / `NodeClientDb.search` added. Removed
  `escapeTantivyKey` — `filters=` is exact `property:"value"` pairs, no
  query language.
- Fix: [#1358](https://github.com/atomicdata-dev/atomic-server/issues/1358)
  Cloud Vault restore on Safari (and any WebCrypto signer) failed with "no
  wrapper in this envelope accepted that credential". The agent vault proof
  asked the signed-in agent's provider for a signature, which on WebKit is
  WebCrypto with a randomized nonce — a different valid signature every
  call, so the KEK never matched. The proof is now derived once with noble
  (RFC 8032, matching the server) from the raw key at sign-in and persisted
  beside the keypair. When no stored proof exists, a live signature is only
  accepted if signing twice reproduces it.
- Fix: signing in with a passkey or secret on a browser that has no
  control-plane session no longer ends on "Your data is on another device"
  with nothing to do. The connect-device step checks for a session first
  and, when there is none, offers sign-in on the portal (or the device-link
  panel in a webview that cannot hold the cookie).
- Onboarding: the connect-device screen names one way in — restore from the
  backup, sign in to the account that keeps it, or the second-device routes
  — and folds the rest under "…or bring it over from another device".
- Sidebar drive switcher is a two-part control: the drive's emoji or icon
  (home for the private drive) plus its name, both halves bordered like a
  segmented button.
- Quick-create class shortcuts reveal on hover and stay hidden on touch
  (the New page still has them).
- [#1338](https://github.com/atomicdata-dev/atomic-server/issues/1338) Title
  row on touch and narrow screens: the Add icon / Add cover ghost buttons
  next to a page title only render where the viewport can hover and is at
  least 600px wide; elsewhere they appear in the resource context menu.
- Title editor wraps like the heading (a textarea that grows with the text)
  instead of becoming a single-line input that scrolls sideways. Clicking a
  title places the caret under the pointer instead of selecting the whole
  title (a freshly created resource still selects its placeholder). The
  go-to-parent arrow on narrow nav bars is gone.
- The unsaved-changes asterisk is gone. Autosaving editors set the dirty
  flag between every keystroke and its commit, so it blinked on every tap
  and told the user nothing; the sidebar sync item already spins while
  commits are in flight.
- `@tomic/lib` live collaboration speaks binary `EPHEMERAL`. Edits in progress, cursors and drive presence are sent and received as `EPHEMERAL (0x40)` frames (`encodeEphemeral` / `decodeEphemeral`, `EphemeralKind`), raw bytes instead of base64 JSON in the `LORO_SYNC_UPDATE` / `LORO_EPHEMERAL_UPDATE` / `PRESENCE_UPDATE` text frames, which are gone. `WSClient.sendLoroSyncUpdate`, `sendLoroEphemeralUpdate` and `sendPresenceUpdate` now take `(subject, bytes)`; `Store.__handleLoroSyncMessage`, `__handleLoroEphemeralMessage` and `__handlePresenceMessage` take `(subject, bytes)`. The subscribe / unsubscribe frames are still text.
- `@tomic/lib` drive sync speaks binary `SYNC`. The hash-first probe on connect and the reduced reconcile after the RBSR descent are sent as `SYNC (0x30)` with `"probe": true` / `"subjects": [...]` in the JSON tail, and a stale probe is answered with the new `SYNC_RESEND (0x38)` (`decodeSyncResend`, `Tag.SYNC_RESEND`). The text `SYNC_VV` request and text `SYNC_RESEND` answer are gone; the `RBSR_FP` / `RBSR_ITEMS` descent is still text. Servers advertise `sync-probe`; an older server ignores the two keys and runs a full reconcile.
- `@tomic/lib` cleanup. Switching drives now `UNSUB`s the previous drive's fan-out (until now every drive opened in a session kept pushing its commits to the socket). `Store.waitForServerConnected(timeoutMs)` is public and is the one implementation of a wait that existed four times over (`Collection` and two data-browser helpers now use it). Removed: the write-only `serverHasCapability` / `getServerWsCapabilities` cache (the live list is `WSClient.serverCapabilities`), `Store.logIncomingCommit`, the `debugFrame` codec helper and the exported `supportsWebSockets` (all without callers), and a skipped integration test targeting APIs that no longer exist. Liveness constants moved to `liveness.ts`.
- `@tomic/lib` sync protocol follow-ups. The WebSocket client introduces itself with a `HELLO` on open (`CLIENT_CAPABILITIES`, today `commit-ok-slim`), and a server that honours it answers `COMMIT` with a slim `COMMIT_OK` carrying only the commit id; `postCommit` resolves with the commit it signed plus that id, and still accepts the full-JSON ack from older servers. The AUTH proof is bound to the socket: the client signs `{origin}#{nonce}` with the nonce from the server's `CHALLENGE` frame (falling back to the timestamp-only proof after 300 ms on a server that sends none), so a captured proof cannot open a session anywhere else. The outbox drain is pipelined: subjects of one ordering tier (agents, then the drive, then children by depth) are drained up to eight at a time with a barrier between tiers, instead of one round trip per subject (`OutboxDrainContext.tierOf`, `DEFAULT_DRAIN_CONCURRENCY`). A `SYNC_DIFF` no longer pushes raw bytes for a subject the outbox still owns, and the RBSR reconcile no longer offers such subjects; the drain delivers them signed. `ErrorCode.INVALID_SIGNATURE (9)` added. New `websockets.test.ts` exercises the client against a fake socket.
- `@tomic/lib` sync protocol: the WebSocket client now detects a silently dead socket. When the server advertises the `keepalive` capability (in its `AUTH_OK` payload), the client sends a `KEEPALIVE` after 20 s without any inbound frame and closes the socket after 45 s of silence so the reconnect loop takes over; before, a dropped connection stayed "connected" until the next write failed and every push in between was lost. The server's advertised capabilities are exposed as `WSClient.serverCapabilities`. New `WSClient.unsubscribeFromDrive` sends the binary `UNSUB`, which the server now honours. Removed the dead `WSClient.subscribeResource` / `unsubscribeResource` (no callers; the browser is drive-`SUB` only, and the text `UNSUBSCRIBE` frame they sent was never handled). `encodeSync` now writes the length-prefixed hex hash the Rust decoder expects. `ErrorCode.AUTH_FAILED (8)` added. A shared golden-vector test (`protocol_vectors.json`, generated by the Rust codec and mirrored into `browser/lib/src/`) pins the TypeScript and Rust codecs byte-for-byte.

## [v0.41.0-beta.4] - 2026-09-03

- Desktop & mobile apps: the Sync page now offers "Sync with AtomicServer.eu" and Cloud Vault, and "Restore account" works from inside the app. The apps embed their own node, which names no provider, so the store builds now bake in the AtomicServer.eu address. A webview cannot hold the portal's session cookie, so instead of being sent to the portal's sign-in page (a dead end: the magic link opened in another browser), the app links to the account by device code — the same flow the Sync page uses — and the restore check re-runs in place once linked. The welcome-screen button is now labelled "Forgot it? Restore from AtomicServer.eu".
- Fix: signing in with a recovery code on the hosted app (an origin without a node) ended on "/" with "Offline: resource not available locally", and the Sync page said there was no backup. The drive defaulted to the origin, which nothing serves there; boot and sign-in now open the account's key-derived personal drive instead (node-backed origins such as atomicdata.dev keep the origin as their main drive). When the vault has nothing for that drive, the connect-device step says why, and offers the account's most recently backed-up drive if it has another one.
- Fix: a returning account on a device whose key was stored before the derived personal-drive subject was recorded beside it failed with "Cannot work out this account's private drive: its key signs non-deterministically…" as soon as it needed its home (sign-in, creating a drive). The non-extractable key cannot recompute the subject, but the Agent resource carries the pointer, so the Store now reads it from there (local copy, then the server) and caches it for the session.
- Fix: a Commit resource could end up in the sync outbox and stay there for good. Commits are immutable, so the server refused every attempt ("Commits cannot be edited."), the Sync page kept showing "Changes pending", and each reload retried. The Loro subscriber already skipped `did:ad:commit:` subjects but not the older `https://host/commits/<sig>` form; `@tomic/lib` now recognises both (`isCommitSubject`), never queues them, drops any that an older build persisted, and treats "Commits cannot be edited" as a terminal error.
- **Cloud Vault is on for everyone.** On a managed origin, every account's personal drive now gets an encrypted backup without asking: signing in (with a secret, a recovery code or a passkey) enrols the drive and backs it up, the app backs it up again a minute after the last edit and when the tab goes to the background, and an account that was already signed in is enrolled at the next load. A second browser that signs in and finds none of the data restores it from the vault before showing "your data is on another device"; the error page for a drive this device never held offers the same restore. Turning backup off on the Sync page is remembered, so the next sign-in does not switch it back on. Self-hosted installs are unaffected (no control-plane session, nothing to enrol). Every pass still seals the whole drive; incremental export is next.
- Fix: the hosted build no longer treats the origin it is served from as its server when that origin runs no atomic-server. The managed deployment serves the app from a shared static origin; someone on the free tier has no node, and the app kept retrying a WebSocket to that origin (with an error toast on the first screen), polled `/server` for a JSON document that came back as `index.html`, parked every commit in the outbox, and the Sync page counted the origin as "1 other device" and called Cloud Server "a migration, not a backup". The hosted build now asks its origin once at boot (`GET /server`); when the answer is not a node, the Store keeps the URL but opens no socket (`StoreOpts.connect: false`, `@tomic/lib`; the choice sticks to that URL, so the drive defaulting to it through `setDrive` does not open one after all), a new identity and its personal drive are registered local-only from their first save (the same routing the demo uses), and switching Cloud Server on promotes both to the assigned node. Source builds and the desktop shell are unaffected: only the hosted distribution probes.

## [v0.41.0-beta.3] - 2026-09-01

- Fix: opening a v1 document no longer shows a read-only page with an "Update Document" button that throws. Writable v1 documents migrate silently to the Loro-backed editor. Leftover Yjs-era V2 bodies still convert, but `yjs` is loaded only when those bytes are present.
- Fix: opening an adopted HTTP drive no longer moves the home server. A bare origin (`https://host`) is still a server switch; an HTTP subject with a path is a workspace and is fetched cross-origin, so a pre-DID drive on `atomicdata.dev` cannot take the session with it (websocket, DID auth, every later fetch).
- Fix: opening a filled table no longer flashes rows (or sidebar children) in the wrong order. Local queries are unsorted; hydrating each member used to optimistic-add them in arrival order before the client-side sort landed. The sidebar also listed every table row until the resource's class arrived. OPFS cold-load could shuffle array properties the same way by merging a JSON-AD-seeded LoroList with the stored snapshot. Reloading a table after a cell edit no longer leaves the page stuck loading: an OPFS snapshot replace was importing the same bytes twice and could drop `isA`. Table totals now re-query after the edit is queued to OPFS, so a sum follows a cell change without a reload.
- Dev: React Compiler now runs through native `oxc-transform-react` instead of `babel-plugin-react-compiler`. JSX/TS and Fast Refresh share that pass. styled-components `displayName` comes from Oxc's built-in plugin on Vite's oxc pass, so Babel is gone (`babel-plugin-react-compiler`, `babel-plugin-styled-components`, `@rolldown/plugin-babel`). Vite dev no longer pays a Babel tax per module (files that used to take ~100ms now land around ~10ms). Oxlint 1.79's compiler-powered Rules of React (`react/immutability`, `react/purity`, `react/error-boundaries`, …) are on; `set-state-in-effect` / `refs` / `static-components` stay warn until those call sites are cleaned up.
- Fix: clicking a button in the navbar no longer draws a blue outline around the whole bar. The bar used `:has(:focus)`, which matched mouse clicks; keyboard focus still shows on the button itself.

## [v0.41.0-beta.2] - 2026-08-01

### Atomic Browser

- Fix: asking the assistant to point a dashboard block at a different table left its view, its measured column and its chart's buckets pointing at the old one — so the block kept filtering and aggregating against a table it no longer showed, quietly answering nothing rather than visibly breaking. Those three are now cleared when the table changes, unless the same request replaces them. The Configure dialog already did this; the tool did not.
- Fix: asking the assistant to change what a block measures without naming a column — "average it instead of summing" — emptied the block instead. It now keeps the column the block already measures and changes only the function, and says so plainly when there is no column to keep. The same gap in the Configure dialog is closed too: Save is disabled while a sum or average has nothing to measure, rather than saving a block that renders as an em-dash.
- Fix: a dashboard's stored layout is now only what the page actually honours. It held `x`/`y` coordinates alongside each block's size, and nothing ever read them — so a layout the assistant computed, or a position implied by the block menu, was silently ignored while the blocks simply flowed in order. Layout is now size plus order, which is what both the menu and the grid can express; coordinates will come back with drag-and-drop, together with a renderer that honours them. Dashboards created before this keep their sizes.
- Fix: creating a dashboard from the New menu dropped you into the generic resource form, which renders its blocks and layout as raw JSON fields — a create screen asking you to hand-write a layout before any blocks exist to lay out. It now asks for a name and takes you to the dashboard, which is where blocks are added.
- **A dashboard can have the button too.** A new **Button** block puts a create button on a dashboard — press it and the numbers beside it move, on the page you are already looking at, which is what makes a dashboard something you use rather than something you read. It stores exactly what a table's own create button does and is configured through the same form, so there is one thing to learn. (A number updates immediately; a table block embedded beside it shows the new row after a reload.) Note that an embedded table block already carries its view's row-action buttons and its quick-add bar, so those needed no block of their own.
- **One-tap create.** A button above the rows that makes one: type "Milk" and press, or press once and the moment is recorded. Configure it from a view's tab menu — a label, optionally a field to type into, and optionally one value the new row starts with, which reuses the same four verbs the row actions use (so "Log set" can stamp today's date and create in a single press). With no field it is the whole interaction; with one it clears after each press, and Enter works, so a shopping list can be filled at speed. Stored on the View as `view-quick-add`, so two views of a table can offer different buttons, and `create_table` / `configure_view` take `quickAdd`. Shipped on the Grocery list ("Add item"), Plant care ("Add plant") and Workout log ("Log set").
- **Row actions: a button on every row, as configuration rather than code.** The verb a mini-app is mostly made of — "Watered", "Mark done", "+1", "Got it". Four kinds, and deliberately only four: stamp the current time into a date column, write one fixed value, flip a checkbox, or add a fixed amount to a number (use −1 for a "one fewer" button). Add one from **Add column → Action**, edit or remove it from its column heading. A button that records state reads as engaged once it has, so it doubles as the readout, and it goes busy then confirms while the commit is in flight. Every press is an ordinary commit on that row: rights-checked, synced, in history, undoable — and no buttons render at all for someone who cannot write, since an action that is going to be rejected is worse than none. Stored on the View as `view-row-actions`, so two views of a table can offer different buttons. The Plant care template now ships **Watered**, Inventory **+1 / −1**, and the Grocery list **Got it**. `create_table` and `configure_view` take `rowActions`, and `describe_table` reads them back.
- Fix: a computed column now updates as soon as the column it derives from changes. It used to show whatever it computed when it was first drawn — edit the quantity and its "Quantity × Unit price" stayed put until you reloaded the page; press a row action that stamps a date and the "days since" beside it did not move. The React Compiler was caching the computation against a resource identity that never changes, because the store mutates resources in place. Computed columns are now functions of the values they read, and each cell subscribes to exactly those. The timer's Start/Stop button had the same latent problem and is fixed with it. (A computed cell is still blank on the trailing row you are typing into, until that row is saved and redrawn.)
- Fix: the Grocery list template could not be created at all. Its "Meat & fish" aisle option became the shortname `meat--fish`, which the slug rule rejects — `stringToSlug` stripped the `&` only _after_ collapsing repeated dashes, leaving the two dashes it had been sitting between. Any name with punctuation between words hit this.
- Fix: a dash could not be typed into a shortname field. The slug rule above is a _final_ form — it drops leading and trailing dashes — and the input applied it to every keystroke, so the `-` you were typing was trailing for exactly as long as it took to press the next key: "is-valid" came out as "isvalid". Hyphenated shortnames were untypeable, in the ontology editor and every New Resource form. The field now keeps a single trailing dash while you type and settles it on blur, validating the settled value so no "Invalid Slug" flashes between the words of a name.

- **Dashboards.** A new kind of page that composes blocks over your data: a number, a chart, an embedded table, a note — arranged on a grid. Four block kinds in v1. A **number** is a sum, count, average, min or max computed by the store over _every_ row a view matches, so it is exact regardless of paging, and it can measure a computed column (a total duration, quantity × price) as well as a stored one. A **chart** is the same number per bucket, drawn as horizontal bars, bucketed exactly or per day or month. A **table** block embeds the real table — cells stay editable, columns sortable — rather than a snapshot. A **note** is markdown. Blocks are resources of their own, so the same dashboard can be built by hand and by the assistant: `create_dashboard` builds one in a call (resolving column and view names, laying blocks out automatically), `describe_dashboard` reads it back, and `configure_block` changes one field without disturbing the rest — everything the tools can write, the per-block Configure dialog can change. A stat or chart block points at one of the table's _views_ and borrows its filters, so "open issues" is the open-issues view plus a count instead of a filter restated in two places. Create one from the New menu.

- Fix: a filtered view kept a row whose value had stopped matching it. Raise a "Quantity at most 3" row to 40 and it stayed in the Low stock view — across a reload, because the local database's index still listed it as a member. Editing a row out of a filtered view now removes it, editing one into a filter still adds it in the right sorted position, and an edit that keeps a row in the view but changes what it sorts by no longer lists it twice.

- [#1236](https://github.com/ontola/atomic-server/issues/1236) [#1238](https://github.com/ontola/atomic-server/issues/1238) **A computed column can be totalled.** Sum a table's Durations, average a days-since, add up quantity × price — and break any of it down per day, month or category. The store evaluates the column as it aggregates, so the number covers every row the view matches rather than the page on screen, and a running timer entry counts its time so far. Totals of a computed column read the way the column does: a sum of durations is `5:30:00`, not `19800000`. This closes the gap that made the Time tracker's day totals impossible, and that template now ships them. `create_table` and `configure_view` take `computedColumn` next to `column`, so the assistant can total one too.
- Fix: when an AI request failed, the chat did nothing at all — no message, no error, just silence, with the only evidence a line in the browser console. An unreachable Ollama, a rejected API key or a model that doesn't exist now says so under the input, naming the provider and quoting its reason, with a Try again button. A turn that dies mid-answer shows its error too: the failure was already recorded on the message, but nothing ever rendered it.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **Eleven new table templates**, and not one of them ships a renderer: Expenses, Deals (CRM), Job applications, Project tasks, Reading list, Grocery list, Workout log, Plant care, Inventory, Guest list and Bookmarks, next to Issue Tracker and Time tracker. Each arrives configured — kanban and calendar layouts, computed columns (days since you last contacted a deal, when a plant is next due, quantity × price), totals broken down per month or category, its own column order, and a filtered view like Inventory's "Low stock". They are available to the assistant through `list_table_templates` / `create_table_from_template`, which now also reports what each view already computes, so it can start from the closest one and adapt it rather than deriving a schema from scratch. The New Table dialog gives each an icon and scrolls, instead of pushing the name field off the dialog.
- Columns can be `decimal`, not just whole `number`: money, prices, hours and measurements keep their cents. It's a float carrying the FormattedNumber shape the property form writes, so switching one to a currency or a different precision afterwards works as usual. `create_table` takes it too — an amount asked for as `number` would have silently rounded.
- [#1236](https://github.com/ontola/atomic-server/issues/1236) Timer view for tables, alongside table / kanban / calendar. It **is** the table: the same grid, so cells stay editable, columns sortable, resizable and reorderable, keyboard navigation works and long histories stay virtualised. On top of it the timer adds a toolbar — name a thing and hit Start — and two columns: a live-ticking Duration and a Start/Stop button. "One at a time" (on by default) stops the running entry when another starts; turn it off to track several things at once. Its start property lives in the View's `view-group-by` slot, its end in the new `view-end-prop`, and the toggle in `view-timer-exclusive`; a class without timestamp properties gets "Start" and "End" created for it.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **The assistant can now change a table, not just create one.** Five tools: `describe_table` reads back the row class, every column and every view's settings (sort, filters, visible columns, computed columns, totals); `configure_view` changes a view in place and touches only the fields it's given, so setting a sort can't drop the filters; `add_table_columns` adds columns to an existing class _and_ appends them to the views that keep an explicit column list (a column missing from that list is hidden, which is why adding a property alone wasn't enough); and `list_table_templates` / `create_table_from_template` start from the catalogue instead of re-deriving a schema. `create_table` grew to match: per-view `sortByColumn` / `sortDesc` / `filters` / `columns` / `columnOrder`, and `relation` columns can name their target class so the cell picks from that class instead of searching everything. Column names are resolved case-insensitively by name, shortname or subject throughout, and a select filter accepts an option's name. The whole chain is covered end-to-end by an e2e test that scripts the model and lets the tools run for real.
- **Column order is per-view configuration now**, and covers every kind of column. Drag any heading — including a computed column or the timer's Start/Stop — and the order is saved on the View (`view-column-order`, a list of column keys), so two views of the same table can arrange the same columns differently. A column added after the order was saved appears at the end rather than disappearing, and a LocalizedText property split per language still moves as one column. The timer view now leads with its Duration and Start/Stop: timing something is the point of that view, so its controls sit where the eye starts instead of past four columns of data.
- Fix: columns a view adds (a computed column, the timer's Start/Stop) could not be resized, and rendered at the 300px default rather than the width they asked for. Two separate bugs: the table re-imposed their default width on every render, throwing away the resize it had just stored; and the grid's size list, when the column count and the stored widths changed in the same commit, appended defaults over the widths using a stale copy. Their heading also matched the header cell's bold instead of a property heading's regular weight, and the grid's 100px minimum column width made dragging a 70px button column snap wider instead of resizing it — the floor is now 40px. Default widths themselves are unchanged: narrow is right for a duration or a button.
- Fix: switching between views whose column counts differ painted the previous view's column widths for a frame, which churned the grid while it settled. The width list is now ignored when it doesn't match the columns on screen, rather than rendered.
- Fix: a totals cell's menu could stop opening after it had been used once. Its trigger button was built fresh on every render, so React remounted it constantly — and the totals re-render on every store event, so a click landing in that window hit a button that no longer existed. The trigger is now one stable component that reads its contents from context. A computed column's totals cell, which genuinely has nothing to offer (the store aggregates stored values), now says so on hover instead of ignoring the click.
- Totals rows read as a summary rather than more data: their own raised background, a firm line above, and each extra row separated from the one before. The value is bold in the regular text colour with a small grey label — in dark mode the label used the near-black `textLight2`, which made "AVERAGE 14,50" almost invisible.
- **More than one totals row.** Add rows from the totals menu and give a column a different statistic in each, so Amount can show a sum on one line and an average on the next. Stored per aggregate as a `row` index; `configure_view` takes it too. A row you add holds nothing until you fill a cell in it, so an empty one is never persisted.
- **Totals now live in a footer row under the grid**, each under the column it describes — click a column's footer cell and pick Sum / Average / Min / Max / Count, the way a spreadsheet does. The row is always in view (the rows scroll inside their own box) and scrolls sideways with the columns, so a total stays under its column. Its left cell shows how many rows the view matches and carries the "break down by…" menu. This replaces the Σ button in the top-right corner and the free-floating totals strip: a number is much easier to read directly beneath its column than in a labelled list somewhere else.
- Fix: totals didn't update when the data changed — they came from the row collection, which patches its pages surgically on an edit rather than re-querying. They now ride a small query of their own (one row plus the numbers), re-read on save/delete with a short debounce. That also means refreshing them no longer clears the grid's pages under the cursor.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **Totals under the table**, computed by the server: a sum, count, average, min or max over **every** row a view matches — filters included, paging excluded — plus an optional breakdown giving one subtotal per distinct value of a column (per project, per status, per day, per month). This is a new query capability rather than a client-side add-up: `Query` carries an `aggregation`, the store walks its own index and returns a handful of numbers on the Collection's new `collection/aggregates` property, and because the browser's local database runs the same Rust code, an offline table shows the same totals. Configure it from the Σ button next to the table's filters, or ask `create_table` for `aggregates` / `breakdownColumn`. Day and month buckets use your timezone, not UTC. Stored on the View as `view-aggregates` / `view-group-by-column` / `view-group-granularity`. Note that a `count` counts the rows you can actually read, which can be lower than `totalMembers` (that one counts raw index hits). Aggregating a _derived_ column isn't possible yet — those aren't stored.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **Derived columns**: a table view can show columns computed from each row rather than stored on it — a live duration, a days-since, an amount, a next-due date. They are configuration, not code: the View lists them in the new `view-derived-columns` (JSON), any view kind renders them, and `create_table` can build them, so a mini-app that needs one is a template rather than a renderer. Five fixed generators, deliberately not a formula language: `difference` (to − from), `elapsed` (the ticking variant, stopping once its end is stamped), `daysSince`, `product` (either factor may be a literal, e.g. a rate) and `offset` (a date plus a number of days). The timer's Duration is now one of them — an `elapsed` over the two timestamps the view already knew about, seeded by the Time tracker template — so it renders in a plain table view too, and the timer keeps only its Start/Stop column. Add one from **Add column → Computed**: the dialog is generated from the generator itself, so it only offers columns that fit each argument (date columns for a duration, number columns for a multiplication) and lets you type a fixed number where one makes sense. Its heading carries the menu that edits or removes it again. See `planning/table-templates-and-mini-apps.md`.
- Table columns may now be **virtual** — rendered by the view rather than read off a Property (`TableColumn.virtual`). The grid stack was already generic over its column type, so this cost the editor nothing, and it's the seam that future derived columns and row actions plug into. See `planning/table-templates-and-mini-apps.md`.
- The table's filter and property menus are both plain dropdowns now, instead of one dropdown and one popover full of checkboxes. Each has a header saying what it does, whole rows are the click target rather than a small checkbox, shown properties are marked with a check, and both label properties by their human title. Toggling a property leaves the menu open — `DropdownMenu` items take a new `keepOpen` for menus that toggle state rather than navigate away. Properties a view is structurally built on (a timer's name/start/end, a kanban's or calendar's group-by) are shown locked with a reason instead of offering a toggle that the view would ignore.
- A table's active view is now in the address bar (`?view=`), so a view is linkable, survives a reload, and Back/Forward moves between views instead of leaving the page. It used to be session-only React state.
- Fix: creating a column did nothing in a view that had ever had its columns reordered or toggled. `view-columns` treats any property it doesn't list as hidden, so a newly created one landed on the class and was immediately invisible. New properties are now added to the active view's columns as they're created — same for adding an external property.
- Fix: adding the first filter (or sort) to a table sometimes silently discarded it. Doing so lazily creates the View that stores it, which flips the active view and re-reads its config — racing the write that prompted the creation, and hydrating local state back to empty when it won. The freshly created View is now excluded from that re-read: it exists to hold what's already in local state.
- Fix: typing into a table cell could eat the first character. That keystroke both opens the editor and is written to the resource, but the write is async, so the editor mounted with the pre-keystroke value and the rest of the typing replaced it. The editor is now seeded with the character synchronously, and hands control back to the resource on its next edit.
- [#1236](https://github.com/ontola/atomic-server/issues/1236) A **Time tracker** table template, next to Issue Tracker: Start / End / Project columns with a timer view ready to go. `create_table` can now also build `calendar` and `timer` views (it was limited to table and kanban, so the assistant could never make a calendar), with a new `endColumn` for the timer's end property.
- Fix: an entry started from the timer toolbar was saved but not shown until a reload. The grid holds its member count in a ref, so bumping it renders nothing on its own; the collection is refreshed too now. The failure path also no longer swallows errors silently — it logs and shows a toast.
- Fix: filters did nothing in the kanban and calendar views. The filter dropdown is offered for every view kind, but the row of filter chips was rendered only inside the table branch, so a filter added anywhere else had nowhere to appear and silently never applied.

- Passkey-first account backup. Managed onboarding no longer hands you a second secret to write down: a passkey (WebAuthn PRF) wraps the backup by default, so the common path is a single prompt. The agent secret isn't shown at all when a backup exists, since it stays recoverable from Settings. Only a device-bound passkey (BE flag clear) interrupts to offer a recovery code — the one case where losing the device really does lose the account. PRF is evaluated during credential creation, so enrolling costs one prompt on browsers that support it, falling back to a second assertion where they don't.
- Device lock (Settings → This device): never, on browser close, or after 15 minutes or 1 hour of inactivity. Enforced by withholding the stored keypair at boot rather than via `sessionStorage`, which browsers restore along with tabs — a restart used to come back unlocked.
- Per-agent encrypted local databases. The single per-origin `atomic_data.redb` is split into one OPFS database per agent (a shared plaintext anonymous DB when signed out), each encrypted at rest with XChaCha20-Poly1305. A random 256-bit key per agent is wrapped by HKDF of the agent's private key — the agent key wraps, it never encrypts bulk data. After sign-out or an agent switch a session can no longer read the previous agent's cached private data, without wiping the cache.
- Peer-to-peer video and audio calls in the meeting panel, via Trystero (WebRTC with Nostr signaling). The meeting subject is hashed into the room id and doubles as the signaling password, so only participants can join or read the handshake, and media never touches a server. The call UI ships in a lazy chunk, so the ~24 kB gzipped library is only fetched when someone starts a call. Mentioned in [#1127](https://github.com/atomicdata-dev/atomic-server/issues/1127).
- [#1235](https://github.com/atomicdata-dev/atomic-server/issues/1235) Emoji v1: give any resource an emoji glyph from its context menu or title, shown in the sidebar, search results, cards and inline references.
- Cover images: set an image File as a decorative banner at the top of a resource's page, with an avatar cropper and client-side image resizing. Drag the banner to reposition it and release to save — a wide crop rarely has its subject in the middle — and pick an image you've already uploaded instead of adding a new one.
- The search overlay's "Start AI Chat with ..." now sends your query as the chat's first message. It previously used the query as the chat's title and opened an empty chat, so the thing you asked for was never actually asked.
- Fix: the table grid is sized to the space actually below it rather than a flat `80vh`, which overflowed the viewport and pushed the last rows out of reach once a cover image sat above the table.
- Colorful mode — a new appearance setting that tints the sidebar and navbar with tones of the main color instead of the neutral grey ramp, so no grey sits on a colored surface. Content and text stay neutral for readability. Off, the theme is byte-identical to before. The main-color presets are now also the default tag palette, replacing the neon tag colours.
- Dark mode for the static loading screen, and dark-aware `theme-color` metas so OS and browser chrome match the app.
- The sidebar drive header is unified into a single component.
- Meetings now start from their own page rather than the top bar or the More menu.
- Added an `/app/new-drive` route, for the managed portal's "+ New drive".
- Copy / duplicate a resource. New `copyResource` in `@tomic/lib` carries a resource's content (propvals and classes) into an independent new resource under a chosen parent, without its identity, ACL or history. Unlike `forkResource` the copy has no link back to the source and can't be merged into it; copying a fork yields a plain resource. The name gets a " (copy)" suffix so a duplicate sitting next to its source is tellable apart.
- Fix: only origins that answer `/server` are registered as known servers. The managed deployment serves the SPA from a shared app origin that isn't a node, and listing it offered a "Switch" pointing the store at something that couldn't answer. A non-answer also removes entries that older builds added blindly.
- Fix: Kanban view polish — the column header is merged into one rounded card, plus icons, a header pill, a clearer add-card affordance and an empty-column state.
- Fix: restored the New Meeting quick-create button.
- Fix: genesis and other internal properties are hidden from the resource form and property lists.
- Fix: the slash-menu suggestion handlers are guarded against an unset component.
- Fix: DOM prop leaks, missing list keys, and Enter-to-submit in New Table.
- Fix: editor state updates that ran during the render phase moved into effects.
- Fix: the ClientDb's lock-steal recovery got a realistic settle budget.
- Patched 45 real npm vulnerabilities via scoped pnpm overrides.

## [v0.41.0-beta.1] - 2026-07-22

### Atomic Browser

- [#1069](https://github.com/atomicdata-dev/atomic-server/issues/1069) Content localization / i18n: a new `LocalizedText` property type with a per-language input (`InputLocalizedText`), a table-editor cell with a language switcher and column-language chip, a New Column category + datatype picker, and a read-only view that resolves the visitor's preferred language. `@tomic/cli` codegen maps the datatype to the `LocalizedText` TS type.
- [#1069](https://github.com/atomicdata-dev/atomic-server/issues/1069) The Next.js and SvelteKit site templates (`create-template`) now scaffold two-locale sites out of the box: locale-prefixed routing, a translation-sibling switcher, hreflang tags, group-fallback listings, and a footer language switcher.
- Add `@tomic/edit-mode`: turn any page rendered from Atomic Data into a guest-editable, local-first clone — an "Edit this page" affordance backed by a guest agent and a local-only drive in the visitor's browser. Every edit is a signed CRDT commit; nothing reaches a server.
- Renamed the hosted product from AtomicCloud to AtomicServer.eu.
- Fix: the meeting side panel's title no longer collides with the main page title's view-transition (which silently skipped the transition when both were on screen).
- Fix: the demo's guest identity no longer flashes "Error loading resource" across the UI.
- Fix: the "Sign in to your account" onboarding button no longer sends self-hosted users to a hardcoded dev portal URL.
- Cloud Sync: the Sync page now shows the connected node's per-drive usage (resources + bytes, from the generic `/drive-usage` endpoint), with plan quota for managed nodes, plus a "Manage account & plan" link for managed nodes. The redundant Drive row was removed.
- Cloud Sync identity: when signed in to Cloud Sync with a device agent that differs from the account, the app now converges **silently** — it adopts the device agent (when the account has none) or restores the account's agent — instead of blocking on a "resolve identity mismatch" screen that surfaced agent DIDs.
- Favorites: favorite any resource from its context menu and find it back in a new sidebar **Favorites** panel.
- The per-user index lists — `favorites`, `sharedWithMe` and saved `drives` — are now stored on the user's **private drive** (the per-user home index) instead of on the Agent identity resource. They hold pointers to resources that may live on any drive, resolved per-pointer.
- The **Favorites** and **Shared with me** panels now sit at the bottom of the sidebar (above App settings) rather than scrolling with the active drive's tree.
- Updating any of these lists now surfaces an error toast on failure instead of failing silently.

## [v0.41.0-beta.0] - 2026-06-22

### Atomic Browser

- Search UI is redesigned, now as an overlay, feels like a command bar, shows preview of selected item.
- New navbar design. Always access to important features & hierarchy.
- New onboarding UX for new users & drives.
- Switch to OxLint
- #1178 Sync protocol
- Client persistence & indexing with wasm #1175
- Simplify agent & drive creation in client APIs #1177
- Add `drive` to Store. This used to be a React API, but it's useful in far more contexts.
- #1163 New settings page design with search
- #1160 Switch to Oxlint + Oxfmt
- Comment all the things - chatrooms for every resource #898
- #1198 Kanban view, issue template and Calendar view
- #1229 Presence, see what users are looking at and follow their activity
- [#741](https://github.com/atomicdata-dev/atomic-server/issues/741) New feature: A brand new document editor with realtime collaboration and a fast and efficient editing experience.
- [#741](https://github.com/atomicdata-dev/atomic-server/issues/741) New feature: A brand new document editor with realtime collaboration and a fast and efficient editing experience.
- [#951](https://github.com/atomicdata-dev/atomic-server/issues/951) New feature: Atomic Assistant, AI chat interface with support for custom agents, MCP servers and more. Bring your own OpenRouter key or use Ollama to host your own models.
- [#459](https://github.com/atomicdata-dev/atomic-server/issues/459) New feature: Add tags to your resources to better organize your data. Search for resources with specific tags in the search bar with `tag:[name]`.
- [#1118](https://github.com/atomicdata-dev/atomic-server/issues/1118) New feature: AtomicServer is now also available in German, Spanish and French. Change your language on the settings page.
- [#981](https://github.com/atomicdata-dev/atomic-server/issues/981) Fix bug where the service worker would not update cache with updated code.
- [#989](https://github.com/atomicdata-dev/atomic-server/issues/989) Added an edit button to the resource selector inputs.
- [#992](https://github.com/atomicdata-dev/atomic-server/issues/992) Fix Searchbox overflowing when displaying long names.
- [#999](https://github.com/atomicdata-dev/atomic-server/issues/999) Fix parseMetaTags character escape issue.
- [#1014](https://github.com/atomicdata-dev/atomic-server/issues/1014) Fix date input always showing required error even when filled in.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1005) Showcase standard properties in the resource selector
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Add 'New Property' button to the property list in the ontology editor.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Fix disabled resource selectors still get highlighted on hover.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Add 'open' option to classes and properties in the ontology edit view.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Updated the look of the resource selector and made it more responsive.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Add info dropdowns to different sections of the ontology editor for more information about the section.
- [#1219](https://github.com/atomicdata-dev/atomic-server/issues/1219) Add filters to tables
- [#1219](https://github.com/atomicdata-dev/atomic-server/issues/1219) Persist table views
- Persist table views across sessions and fix table sorting, drag-and-drop, and column-width resizing.
- Add inline AI model selection with optional models, slash commands, latest-used models, improved keyboard input, and clearer checking/blocking states.
- Save AI chats in the user's personal drive and fix chat title generation, sticky scrolling, creator/date refresh, and indexing submission.
- Add a clipboard fallback for insecure local origins so onboarding secrets can still be selected/copied when `navigator.clipboard` is unavailable.
- Improve insecure-context behavior by falling back visibly when Web Locks or OPFS are unavailable.
- Improve offline and local-first UX, including spinner behavior in offline mode and server-only fallback paths.
- Fix resources and collections rendering blank when a snapshot arrives before Loro WASM is ready.
- Fix theme setting persistence, tag queries in the navbar, and long-name search overflow.

### @tomic/lib

- `resource.props` is now writeable: `resource.props.name = 'New Name'`.
- Added `store.preloadResourceTree()` method, see docs for more info.
- Fix generated ontologies not working in a Next.js server context.
- Fix types masquerading as esm module in cjs build.
- `store.search()` now handles multiple values for the same property correctly.
- [#1077](https://github.com/atomicdata-dev/atomic-server/issues/1077) Fix bug where resource.new would not be set back to true when saving fails.
- Added `ResourceEvents.LoadingChange` event on `Resource` to listen for changes to the loading state of the resource.
- Added `resource.stable` property to `Resource` to get a stable reference to the resource, even when it is proxied.
- Added `resource.merge()` method to merge a resource into another resource while preserving local changes on the current resource.
- `store.addResources()` now merges incoming resources with resources already present in the store instead of replacing them.
- SEMI BREAKING CHANGE: When using generated types by cli, @tomic/lib now requires them to be generated by @tomic/cli v0.41.0 or above.
- BREAKING CHANGE: The `StoreEvents.ResourceRemoved` event callback now only receives the subject of the resource instead of the resource itself.
- Add a WASM-backed ClientDb with OPFS persistence and indexing.
- Fix ClientDb offline durability by flushing OPFS writes in the browser worker.
- Release the ClientDb leader lock on destroy, fixing stale Firefox leaders.
- Degrade gracefully when browser persistence APIs are unavailable, including no-OPFS/no-Web-Locks server-only mode.
- Fix local edits persisting across the ClientDb drain.
- Fix `lastCommit` preservation during `Resource.merge()` to avoid accidental genesis saves.
- Preserve cosmetic datatypes and migrate JSON/resource datatype tags through Loro serialization.
- Migrate to URL-safe Base44 for generated identifiers and auth compatibility.

### @tomic/react

- BREAKING CHANGE: `useCanWrite` now only returns a boolean. There is no longer a message returned.
- BREAKING CHANGE: `useCanWrite` does not take an agent as argument any more and only checks the agent set in the store. If you need to explicitly check a different agent, use `await resource.canWrite(agent)`.
- BREAKING CHANGE: `useDebounce` and `useDebouncedCallback` are no longer exported.
- BREAKING CHANGE: @tomic/react now requires React 19.2.0 or above.
- Added `useDebouncedSave` hook.
- Added `VirtualizedCollectionList` component.
- Add a cjs build.

### @tomic/cli

- [#983](https://github.com/atomicdata-dev/atomic-server/issues/983) Give clear error when name collisions are found in an ontology.
- Generates class definitions that enables doing: `resource.props.name = 'New Name'`;
- [#1071](https://github.com/atomicdata-dev/atomic-server/issues/1071) Fix bug where classes and properties with 'name' props would lead to invalid generated typescript code.
- Generated ontologies now base import extensions on the tsconfig.json file. (moduleResolution: bundler will remove the .js extensions in imports)
- Fix generated ontology output for Next.js server contexts.

### @tomic/svelte

- [#700](https://github.com/atomicdata-dev/atomic-server/issues/700) Update to Svelte 5. There are significant changes to the API.
- BREAKING CHANGE: Dropped support for Svelte 4 and below.
- BREAKING CHANGE: `getResource()` now returns a reactive proxy instead of a readable store.
- BREAKING CHANGE: `getResource()` now takes a function returning a subject instead of the subject directly. e.g. `getResource(() => 'https://my-atomicserver.com/my-resource');`.
- BREAKING CHANGE: Removed `getValue()`. It is no longer needed. Instead use `resource.props.name` directly or do `const name = $derived(resource.get(core.properties.name));`.
- BREAKING CHANGE: Removed `initStore()`. You now need to set your store on a context using `createAtomicStoreContext()`.
- BREAKING CHANGE: Removed `loadResourceTree()`. It is now a method on `store`: `store.preloadResourceTree()`.
- Added `createAtomicStoreContext()` and `getStoreFromContext()`.

### @tomic/create-template

- [#700](https://github.com/atomicdata-dev/atomic-server/issues/700) Update SvelteKit-site template to Svelte 5 and the new @tomic/svelte.
- [#966](https://github.com/atomicdata-dev/atomic-server/issues/966) Add NextJS template.
- [#1036](https://github.com/atomicdata-dev/atomic-server/issues/1036) Provide clearer errors when resources couldn't be fetched.
- [#993](https://github.com/atomicdata-dev/atomic-server/issues/993) Fix template not working when the drive subject has a path after the origin.

## [v0.40.0] - 2024-10-07

### Atomic Browser

- [#952](https://github.com/atomicdata-dev/atomic-server/issues/952) Add templates containing pre made ontologies and resources.
- [#970](https://github.com/atomicdata-dev/atomic-server/issues/970) Add "show commit" button in History
- [#968](https://github.com/atomicdata-dev/atomic-server/issues/968) Allow users to pick files by entering a subject into the file picker search bar.
- [#969](https://github.com/atomicdata-dev/atomic-server/issues/969) Fix markdown editor sometimes doesn't update the value after saving.
- [#975](https://github.com/atomicdata-dev/atomic-server/issues/975) Add create button to resource selector without classtype.
- Fix markdown editor closing the edit page when a button is clicked.
- Add an edit button to the default resource view.

### @tomic/lib

- BREAKING CHANGE: removed the `importJsonAdString` function.
- Added `store.importJsonAD()` method.
- Added support for commonJS modules.

### @tomic/cli

- Fix shortnames in externals.ts are not converted to camelCase.
- Filter out duplicate classes and properties in generated types.

### @tomic/create-template

- Added `@tomic/create-template` package to create new templates.

## v0.39.0

### Atomic Browser

- [#855](https://github.com/atomicdata-dev/atomic-server/issues/855) Add a dialog that shows how to fetch and use the current resource in your code.
- [#896](https://github.com/atomicdata-dev/atomic-server/issues/896) Fix an issue where sidebar items require a double tap on iOS.
- Updated look of the default resource form.
- [#896](https://github.com/atomicdata-dev/atomic-server/issues/896) Fix an issue where sidebar items require a double tap on iOS.
- Updated the look & feel of the sidebar a bit.
- [#893](https://github.com/atomicdata-dev/atomic-server/issues/893) Fix tables not showing any rows when viewing from a different server.
- Fix an issue where the resource-array properties would be set to an empty array instead of removing the property when removing all items in the input.
- Fix an issue where dropdown menus sometimes jump from the upper left corner of the screen.
- Added a full page view for tags.
- Redesigned the ontology page.
- Moved the resource context menu to the top of the page.
- [#861](https://github.com/atomicdata-dev/atomic-server/issues/861) Fix long usernames overflowing on the share page.
- [#906](https://github.com/atomicdata-dev/atomic-server/issues/906) Reset changes after clicking the cancel button in a form or navigating away.
- [#914](https://github.com/atomicdata-dev/atomic-server/issues/914) Fix an issue where changing the subject in a new resource form could update the parent of existing resources if their subject matched the new subject.
- [#925](https://github.com/atomicdata-dev/atomic-server/issues/925) Added export to CSV option to tables.
- [#919](https://github.com/atomicdata-dev/atomic-server/issues/919) Automatically sort classes and properties in the ontology editor.
- [#936](https://github.com/atomicdata-dev/atomic-server/issues/936) Updated the address bar to make it clearer it's also search bar.

### @tomic/lib

- Added `LocalChange` event to `Resource`.
- Added `resource.refresh()` method.
- Removed `cross-fetch`, if your environment does not support fetch make sure to add a polyfill or inject one using `store.injectFetch()`.

### @tomic/react

- BREAKING CHANGE: Removed the `useLocalStorage` hook.
- When using any `useValue` type hook, values will now update when local changes are made to the resource from elsewhere in the app.
- [#257](https://github.com/atomicdata-dev/atomic-server/issues/257) Added `<Image />` component that automatically optimizes images for the web.

### @tomic/svelte

- [#257](https://github.com/atomicdata-dev/atomic-server/issues/257) Added `<Image />` component that automatically optimizes images for the web.

## v0.38.0

### Atomic Browser

- [#845](https://github.com/atomicdata-dev/atomic-server/issues/845) Add option to create instances and tables from the ontology view.
- [#845](https://github.com/atomicdata-dev/atomic-server/issues/845) Add default Ontology option to drives.
- [#841](https://github.com/atomicdata-dev/atomic-server/issues/841) Add better inputs for `Timestamp` and `Date` datatypes.
- [#842](https://github.com/atomicdata-dev/atomic-server/issues/842) Add media picker for properties with classtype file.
- [#850](https://github.com/atomicdata-dev/atomic-server/issues/850) Add drag & drop sorting to ResourceArray inputs.
- [#757](https://github.com/atomicdata-dev/atomic-server/issues/757) Add drag & drop sorting to sidebar.
- [#873](https://github.com/atomicdata-dev/atomic-server/issues/873) Add option to allow multiple resources in relation columns (Tables).
- [#825](https://github.com/atomicdata-dev/atomic-server/issues/825) Folder display styles are now saved locally instead of on the resource. The display style property will now act as the default view style.
- [#884](https://github.com/atomicdata-dev/atomic-server/issues/884) Add new markdown editor.

### @tomic/lib

- [#840](https://github.com/atomicdata-dev/atomic-server/issues/840) Added `store.search()`.
- Deprecated `resource.getSubject()` in favor of `resource.subject`.
- Deprecated `store.getResouceAsync()` in favor of `store.getResource()`.
- Deprecated `resource.pushPropval()` in favor of `resource.push()`.
- Deprecated `resource.removePropval()` in favor of `resource.remove()`.
- Added `resource.matchClass()` method.
- Added `resource.setVersion()` method.
- Added `collection.getMembersOnPage()` method.
- Added `collection.totalPages`.
- Fix lib not working in non-secure browser contexts.
- BREAKING CHANGE: Renamed `resource.getCommitsCollection` to `resource.getCommitsCollectionSubject`.
- BREAKING CHANGE: `resource.getChildrenCollection()` now returns a `Promise<Collection>` instead of a subject.
- BREAKING CHANGE: `resource.createSubject()` no longer accepts a class name as an argument and defaults to a fully random subject.
- BREAKING CHANGE: Resource now keeps a reference to store internally, therefore all methods that required you to pass a store have been changed to not require a store.
  These methods are:
  - `resource.canWrite()`
  - `resource.getHistory()`
  - `resource.getRights()`
  - `resource.destroy()`
  - `resource.save()`
  - `resource.set()`
  - `resource.removeClasses()`
  - `resource.addClasses()`

# @tomic/react

- Added `useCollectionPage` hook.
- Fix bug where `useCollection` would fetch the collection twice on mount.
- `useServerURL` no longer stores the server url in localstorage.

### @tomic/cli

- [#837](https://github.com/atomicdata-dev/atomic-server/issues/837) Fix timestamp is mapped to string instead of number.
- [#831](https://github.com/atomicdata-dev/atomic-server/issues/831) Give clear error when trying to generate types from a non ontology resource
- [#830](https://github.com/atomicdata-dev/atomic-server/issues/830) Create output folder if it doesn't exist
- Use type import in generated files.

## v0.37.0

### Atomic Browser

- [#747](https://github.com/atomicdata-dev/atomic-server/issues/747) Show ontology classes on the new resource page.
- [#770](https://github.com/atomicdata-dev/atomic-server/issues/770) Display more info on the search result page.
- [#771](https://github.com/atomicdata-dev/atomic-server/issues/771) Tables: Don't paste in multiple rows when focused on an input
- [#758](https://github.com/atomicdata-dev/atomic-server/issues/758) Fix Relation column forms to close when clicking on the searchbox
- [#780](https://github.com/atomicdata-dev/atomic-server/issues/780) Use tags in ontology editor to create enum properties.
- [#810](https://github.com/atomicdata-dev/atomic-server/issues/810) Add button to resource selectors to navigate to the selected resource.
- [#764](https://github.com/atomicdata-dev/atomic-server/issues/764) Add option to format numbers as currency in tables.
- [#819](https://github.com/atomicdata-dev/atomic-server/issues/819) Fix number input always shows 'required' even when it's optional.
- [#816](https://github.com/atomicdata-dev/atomic-server/issues/816) Fix bug where editing a column in a table would not submit when pressing enter.
- Fix server not rebuilding client when files changed.
- Added persistent scrollbar to table
- Improved table header UX
- Numbers in tables now respect user locale

### @tomic/lib

- [#798](https://github.com/atomicdata-dev/atomic-server/issues/798) Add `store.newResource()` to make creating new resources more easy.
- Always fetch all resources after setting + authenticating new agent with websockets #686
- Add progress callback to `resource.getHistory()` And increased its performance for resources with a large number of commits [#745](https://github.com/atomicdata-dev/atomic-server/issues/745)
- Fix websocket bug on port localhost with port 80

## v0.36.1

### @tomic/svelte

- Add support for types generated by @tomic/cli

### @tomic/react

- Proxy resource objects instead of cloning them for reactivity.

### @tomic/cli

- Fix bug where an externals.ts file was generated for properties that are already available through @tomic/lib.

### @tomic/lib

- `Collection` is now an async iterator
- Added `getAllMembers` method to `Collection`
- Fix `set` call with equal arrays #715
- Fix ontologies export bug #728

## v0.36.0

### Atomic Browser

- Add table editor #639. Add resource instances using table columns, add properties as rows, paste and copy CSV, keyboard support, sorting.
- Add ontology editor #648. Easily create classes, properties and visualize their relationships.
- Show resource usage (incoming links) in data view.
- New resource selector that uses searchbox #677
- Sidebar redesign
- Switch to current drive button #681

### @tomic/lib

- Add support for typed resources through `resource.props`, powered by `@tomic/cli` (see below)
- When saving a resource whose parent has not yet been saved we now add them to a batch that gets saved later when the parent is saved.
- The `scope` option in `SearchOpts` has changed to `parents` and now accepts an array of subjects instead of a single subject.
- BREAKING: Removed `getCommitBuilder()` method from `Resource`
- Added `hasUnsavedChanges()` method to `Resource`
- Fix bugs in state management: proxy resources instead of clone (for react) #682 #675 #657

### @tomic/cli

- **NEW**
- Generate typescript files from ontologies #665

## 0.35.1

### Atomic Browser

- Improve performance collapsed sidebar items.
- Add article view #319
- Add resource history view
- New subjects have nested paths by default

### @tomic/lib

- BREAKING: `buildSearchSubject` now takes a serverURL instead of the store.
- Fix bug where @tomic/lib would not work in a non-browser context.
- Add `resource.getHistory` method that returns a list of previous versions of the resource.
- Add `store.getResourceAncestry` method, which returns the ancestry of a resource, including the resource itself.
- Add `resource.title` property, which returns the name of a resource, or the first property that is can be used to name the resource.
- `store.createSubject` now accepts a `parent` argument, which allows creating nested subjects.

## v0.35.0

### @tomic/browser

- Move static assets around, align build with server and fix PWA #292
- Add `useChildren` hook and `Store.getChildren` method
- Add new file preview UI for images, audio, text and PDF files.
- Add new file preview types to the folder grid view.
- Fix Dialogue form #308
- Refactor search, escape query strings for Tantivy
- Add `import` context menu, allows importing anywhere

### @tomic/react

- Add more options to `useSearch`

### @tomic/lib

- Add `Store.parseMetaTags` to load JSON-AD objects stored in the DOM. Speeds up initial page load by allowing server to set JSON-AD objects in the initial HTML response.
- `store.createSubject` allows creating nested paths
- Add `Store.postToServer` method, add `endpoints`, `importJsonAdString`
- Add `store.preloadClassesAndProperties` and remove `urls.properties.getAll` and `urls.classes.getAll`. This enables using `atomic-data-browser` without relying on `atomicdata.dev` being available.
- Fix Race condition of `store.getResourceAsync` #309
- Add `buildSearchSubject` in `search.ts` which allows you to build full text search queries to send to Atomic-Server.
- Add `importJSONADString` function, allowing you to import resources from external sources.

## v0.35.0-beta.1

### @tomic/react

#### Breaking changes

- Remove `initAgentFromLocalStorage()`.
- No longer save agent to local storage.

### @tomic/lib

- Add the ability to change the `fetch` function used to fetch resources over http.
- `store.addResource` is depricated in favor of `store.addResources`.
- Add `AgentChange` event on store that is fired whenever the stores agent changes.
- `store.fetchResourceFromServer` now returns the requested resource.
- Add `postCommit` method to `store` that respects the injected `fetch` function.

#### Breaking Changes:

- `uploadFiles()` has moved to `store.uploadFiles()`.
- Remove `Agent.fromJSON()`
- `tryValidURL` and `isValidURL` are now static methods on `Client` and have been renamed to `tryValidSubject` and `isValidSubject`.
- Rename `store.fetchResource` to `store.fetchResourceFromServer`.
- Rename `store.handleError` to `store.notifyError`.
- Rename `agent.checkPublicKey` to `agent.verifyPublicKeyWithServer`.
- Remove `store.errorHandler` and replace with new `StoreEvents.Error` event.

## v0.34.10

- Don't use WebSocket in Node context #280

## v0.34.9

- Fix @tomic/lib exports for non-ts contexts #270
- Fix back / forward buttons in desktop build #263
- Fix `isOffline` for node

## v0.34.0

- Add folders with list & grid views, allow drag & drop uploads #228
- Show icons in sidebar
- Add scoped search, funded by NGI NLnet Discovery #245 #254
- Make web app installable #30
- Add cookie based authentication #241
- Get rid of `useWindowSize` #256
- `canWrite` check should succeed for `publicAgent` #252
- Improve error look & text

## v0.32.1

- Lock ed25519 version #230

## v0.32.0

### Breaking changes

- Changed `null` to `undefined` in many places
- `useTitle` returns an `array` with a `setTitle` function, similar to `useState`
- `resource.getError()` is deprecated in favor or `resource.error`

### New

- Add Hierarchy in sidebar #75
- Add DriveSwitcher #209
- Add `new drive` option
- Add `EventManager` to run custom functions when resources are added / edited / etc.
- Add dialog / modal view #24 #181
- Add bookmark import / reader mode #187

### Fixes & improvements

- Stricter non-null checks, improved typings #220
- Switch from `yarn` to `pnpm` #210
- Various improvements to Dropdown forms #194
- Fix crash in circular parent rendering
- Fix race condition #189
- Make all titles editable #199
- Don't subscribe to search endpoint #200
- Refactor e2e tests
- Render floats
- Hide unsortable items in tables
- Fix dropdown resource select input #222

## v0.31.1

- Fix Dropdown input bug
- Fix autogrow textarea bug

## v0.31.0

- Add ChatRooms #153
- Improve UX for creating new Resources, instantly open new ChatRooms and Documents
- Refer to `previousCommit`s in Commits #140
- Disable websockets out of browser context for `@tomic/lib`
- Fix NPM builds for `@tomic/lib` and `@tomic/react` in non-ts environments #155
- tauri back buttons, new tab external links #115
- Fix concurrency issue with commits #91
- Make bugsnag optional #133
- Add `parseCommit` function
- Use `href` attribute in sidebar menu #148
- Use relative links in About page #149
- Show `CommitDetail` that displays audit info (creator, edit date) #145
- Prevent using `localhost` Agents for external Servers
- Implement `push`, for appending new Resources to (existing) Arrays in Commits.
- Replace snowpack with vite #156
- Use yarn v2 and replace lerna #105
- Prevent default actions for keyboard shortcuts
- Improve cross-OS keyboard shortcuts compatibility (cmd & ctrl, option & alt)
- Fix markdown being shown shortly

## v0.30.6 to 9

- Don't use WebSockets if they're not supported #131
- Fix `@noble` build issues

## v0.30.5

- Switch to `dnd-kit` for drag and drop #92
- Improved views for external resources in Documents
- Add upload dropzone to documents
- Replace `react-helmet` with `react-helmet-async`

## v0.30.4

- `@tomic/react` can now be used without `@tomic/lib` - it re-exports the library
- More performant subject updates in new resource form
- Allow `@tomic/lib` to be used in non-browser (Node) context #128
- Add `useMarkdown` function to `@tomic/react`
- Make search result previews smaller
- Fetch full collections when showing CollectionCard
- `useResource` defaults to not accepting incomplete resources
- Add `sign in` button to invite form
- Rename `baseUrl` to `serverUrl`
- Add `useServerSearch` to `@tomic/react`
- Improve UX in Tauri (desktop) mode
  - Regular Links open in your browser, instead of in Atomic

## v0.30.0

- Add File management views. Preview images and videos, download them. #121
- Add `uploadFiles` method to @tomic/lib. #121
- Add upload field to forms #121
- Fix bug resourcearray input #123
- Add WebMonetization support #124

## v0.29.2

- Add Share settings screen where you can see & edit rights / access control #113
- Add Invite form #45
- Convert Classes to typescript interfaces. Show button for this in Class view. #118
- `Create new resource` button on Drive
- Show multiple parents in breadcrumbs
- Refresh collection on opening page
- Don't auto-accept invites
- Improve server switcher design
- Change default port of localhost to 9883 ([issue](https://github.com/atomicdata-dev/atomic-data-rust/issues/229))

## v0.29.1

- Small fix

## v0.29.0

- Add authentication: sign requests, so the server knows who sent it. This allows for better authorization. #108
- Refactor Error type, improve Error page / views
- Automatically retry unauthorized resources (but I want a prettier solution, see #110)
- `useResource` no longer returns an array, but only the resource.
- Improved EndpointPage (show results, useful for Search, for example)

## v0.28.2

- Added server-side full text search #106
- Add a seperate document show page #2, improved performance in Documents
- Improved `canWrite` hook (more stable, faster)
- Improved sidebar performance (less re-renders)

## v0.28.0

- Improve styling tables and sort dropdown
- It's mostly an `atomic-server` version bump :)

## v0.27.2

- Fix setting Agent bug
- Add constructor to Store

## v0.27.1

- Include all Properties and Classes in the initial view, speeding up the app even further. #65

## v0.27.0

- Parse nested, named JSON-AD resources #98
- Refactor resource status - remove `Resource.status`, prefer `.loading` and `.error`
- Add loading and error status to Property class, include in `useProperty`
- Improve loading and error states for various components
- Refactor `store.getResourceLoading`, `store.fetchResource`, `useResource` - add option to `acceptIncomplete`.

## v0.26.2

- Add [Typedoc documentation](https://atomic-docs.netlify.app/) #100
- Fix bug not showing resource form fields
- Fix circular parent handling in `canWrite`
- Update references to changed resources #102
- Use `ws` instead of `wss` for HTTP connections

## v0.26.1

- Fix `wss` websockets
- Update typescript type exports

## v0.26.0

- Added WebSockets for live synchronization with server #80
- Add Commit parsing #80
- Custom fonts
- Prevent re-applying locally defined commits #90
- Fix race condition commits #91
- Added `opts` parameter to react hooks
- Simplify internal Value model (better performance, less bugs) #88

## v0.25.4

- Fix bugs when setting Agent, validate public key before setting
- Add integration / end to end tests #70

## v0.25.0

- Add Document editor ([demo](https://atomicdata.dev/invite/ycj661fdce8)) #2
- Improved performance and less concurrency bugs while quickly saving resources
- Improve styling (soft background on light mode)
- Add baseURL settings page + edit function in top left

## v0.24.2

- Improve resource selector dropdown, show previews, remove dependency #60
- Add toast notifications #63
- Enable `resource.save()` with custom agent
- Add JSON AD array parser
- ~~Add `default_store.json` resource to the browser to make things snappier~~ removed
- Improve type checking for value initialization and serialization types
- Improve view for nested resources

## v0.24.0

- Match version number of [atomic-data-rust](https://github.com/atomicdata-dev/atomic-data-rust)
- Add Version button to menu
- Disable menu buttons that are not usable
- Improve error view in cards
- Only show plus icon in suitable collections

## v0.0.12

### atomic-data-browser

- Fix tests
- Cleaned up Resource form #51
- Handle usages left in Invites #45
- Add social meta tags #44
- Add fetch as JSON / JSON-AD / Turtle and more to data pages
- Fix bug with invites
- Various styling improvements
- Add Atomic Data Logo
- Dark mode syncs with user
- Scroll to top on page change #47
- Improve keyboard shortcuts for edit / data view #52
- Move Agent settings to sidebar item
- Add rights check
- Change routes and settings structure
- Add Disabled state to form fields
- Improved hotkey handling
- Fix edit subject in resource form

### @tomic/react

- Resources will update when properties change (notify listeners on update)
- clean up package.json / dependencies
- Add rights check hook

### @tomic/lib

- Add `getCommitBuilder` and `hasChanges` function to `resource` and `commitBuilder`
- Add rights check to resource

## v0.0.11

- Split packages, switch to monorepo
- Publish `@tomic/lib` and `@tomic/react` libraries to npm
- Add changelog
