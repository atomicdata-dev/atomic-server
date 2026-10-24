# Flutter AI chat: Markdown, attachments, tool use

The native AI chat (`packages/atomic_chat/lib/src/chat_screen.dart`) had text
bubbles only. Joep asked for Markdown, attachments and an explanation of tool
use, matching the web app's chat (`browser/data-browser/src/chunks/AI/`).

## How the web chat and the account AI work

- The account's AI (`POST /api/ai/chat/completions` on the portal, in
  atomic-saas `src/ai.rs`) is a metered OpenRouter passthrough of
  OpenAI chat completions. It accepts `tools` (function tools), `tool_calls`
  and `tool` messages, and streams the SSE chunks as they are.
- **It does not run tools.** The web app runs its own tool loop in the
  browser (AI SDK `streamText`, at most 8 steps for hosted) with its own tools
  (`useAtomicTools.ts`: `semantic_search`, `get_atomic_resource`, `query`,
  write tools, …).
- **It refuses images and files**: message content must be a string or text
  parts only ("Included AI supports text and tools…"). The web composer
  still offers images for hosted (a bug on the web side); here, photos are
  switched off for the included AI.
- Messages are `ChatLog` entries; `parts` is the AI SDK UI message parts
  (`text`, `file` with a data URL, `tool-<name>` with `toolCallId`, `state`,
  `input`, `output` / `errorText`, `reasoning`, …). Resources given as context
  go in the entry's `ctx`, not in `parts`.

## Done

- [x] Markdown (`markdown.dart` parser, `markdown_view.dart` widget): headings,
  emphasis, inline code, fenced code with language and copy, lists (nested,
  numbered with a start), quotes, links (resources open in the app), tables,
  rules. Tolerant while streaming; only the last block re-parses as an answer
  grows; redraws at most ~30 fps. User messages get inline Markdown only.
- [x] Parts model (`chat_parts.dart`) in the web format; `AssistantApi`
  `chatEntries` / `addEntry` (defaults fall back to text); the app reads and
  writes all parts through the existing `read_chat` / `append_chat_entry`
  bridge calls (no Rust change).
- [x] Tool use: `HostedAi.run` streams `AiEvent`s and runs a client-side tool
  loop (8 rounds) like the web. Tools given: read-only `semantic_search`
  (local search, `{subject,title,chunk}` results like the web) and
  `get_atomic_resource` (`resourceText`). Each call shows as a `ToolStepRow`
  (web labels, spinner, ✓/✗, tap for arguments and a result summary) live and
  from history.
- [x] Attachments: attach button and sheet (Photo library, Camera, File, From
  my drive), chips above the field, thumbnails/chips in sent bubbles, stored as
  web `file` parts. `AttachmentPicker` interface; the app implements it with
  `file_selector` (offline in the pub cache). Text files are sent as text;
  images only to an AI with `acceptsImages` (not the included AI).
- [x] Debug/profile-only pretend AI: `--dart-define=FAKE_AI=1` (compiled out
  of release; on in profile so `scripts/perf_android.sh` can time the chat). Seen on the Phone_A35 emulator: streaming Markdown, tool step,
  photo picker, drive picker, reopened chat history, font scale 1.3, tablet
  split layout.

- [x] Long chats (`chat_window.dart`, see `flutter-performance.md`, "Very
  long chats"): the AI chat, chat room and conversation screens hold a
  window of the chat, not all of it. They open with the newest 50
  (`chatEntriesPage` / `chatRoomMessagesPage` / `conversationMessagesPage`,
  bridge `read_*_page`), read the page before when scrolled within 15 rows
  of the top (a reversed `ListView.builder` with keyed rows and
  `findChildIndexCallback`, so a prepended page and a trimmed end do not
  move what is on screen), keep at most ~500 messages (the far end is
  dropped and read again on the way back), poll with `read_*_after` every
  3 s (rooms and conversations; the AI chat is only written here), and show
  new messages at once only at the bottom; scrolled up they wait behind a
  "Jump to latest" button with their count. Day separators ('Today',
  'Yesterday', the date) per window. Finished messages' Markdown parses are
  shared through a 256-entry cache, so a row scrolled back in is not parsed
  again. The model gets the window (its newest messages), which
  `HostedAi._recent` cuts further to its budget. `ChatWindow.openAt(cursor)`
  is the start of "jump to a message" (a search hit); nothing calls it yet.
- [x] Following a streaming answer (Joep: stop once the screen is full):
  after sending, room is made below the answer so the question sits at the
  top of the list and the answer grows under it; the list follows the
  answer at the bottom while its top is in view, then holds its top at the
  top of the list (`_settle`, after each frame while streaming). A drag by
  the person ends following, and from then on (and while the top is held)
  the growing answer does not move what is on screen. A chat whose last
  answer is taller than the list opens at that answer's start. Tests:
  `test/answer_follow_test.dart`.

## Open

- [ ] Search inside a long chat, and opening a hit at its place
  (`ChatWindow.openAt`): chat text is not in the search index yet.

- [ ] Camera: no camera / image_picker plugin in the pub cache. Implement
  `AttachmentPicker.takePhoto` once one is added.
- [ ] Resource context is not persisted: the web stores it in the entry's
  `ctx`, and `append_chat_entry` only takes `role` and `parts`. Needs a bridge
  function with `ctx` (FRB codegen here is 2.11.1, the crate pins 2.12.0, so
  regenerate with a matching codegen).
- [ ] Images for the included AI: needs atomic-saas to accept `image_url`
  parts (and to bill them). Until then photos are off for it.
- [ ] PDFs and other binary files: no text extraction yet.
- [x] Write tools: the web's tools come through WebToolBridge (embed `?ai=1`,
  `embed/aiTools.ts` denylist). AI edits are held for review like the web
  (`embed/aiReview.ts` over `AIChangesRuntime`; "N changes by AI" bar, Keep /
  Undo, asked before leaving). `edit_document_resource` allowed.
- [x] Message menu (long press): Copy, Regenerate (last reply), Hide (only
  hides: the chat log is append-only; real delete needs a bridge call).
  Readable errors with Try again; out of credits shows the web's text and a
  Buy link (`HostedAi.portal`). AI-generated chat titles, rename by tapping
  the title. Reasoning parts as a folded "Thinking" row.
- [ ] Still missing next to the web: model and agent choice, own providers,
  MCP server settings, /compact, report chat, real message delete, text
  selection inside a bubble (long press is the menu now).
- [ ] Checkpointing a long answer while it streams (the web saves every 1 s);
  here it is saved when it ends (or is stopped).
- [ ] Check on real devices: iOS Files picker (`file_selector_ios`), the system
  photo picker on Android 14+, and a real account's tool calls with Gemini.
