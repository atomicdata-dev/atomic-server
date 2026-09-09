# AI chats are unsaved for exactly as long as the model is working

> **Status:** Diagnosed 2026-08-24, not fixed. Reported from real use: editing
> a source file while the assistant was generating code lost the entire
> conversation, and the chat never appeared in the AI Chats sidebar panel.
> No code changes yet — this note is the diagnosis and the options.

## The symptom

Start a chat in the AI sidebar. Ask for something that takes a while — code
generation with tool calls is the usual case. While it runs, edit a file. Vite
hot-reloads, the component remounts, and the whole conversation is gone: your
prompt, the partial reply, and the chat itself. It is not in the AI Chats panel,
because there is nothing to list.

## Nothing is broken; two correct decisions overlap

**One.** A sidebar chat is an in-memory draft until a real exchange exists, so
the drive does not fill with empty chat resources. The gate is
`shouldFinalizeDraftChat` in `data-browser/src/chunks/AI/AISidebar.tsx`:

```ts
newMessages.length >= 2 && message.role === 'assistant'
```

Until it fires, `persistSidebarMessage` passes `{ saveChat: false,
persistToServer: false }` to `addMessageToChatResource`, so neither the messages
nor the chat resource are written anywhere. The chat resource exists, but only
as a JavaScript object.

**Two.** The assistant's message reaches `onNewMessage` from `useChat`'s
`onFinish` in `RealAIChat.tsx` — when the turn *completes*, not as it streams.

Each is defensible alone. Together they mean the chat is unsaved from the moment
you press send until the reply finishes, and the length of that window is the
length of the turn.

## Why it shows up in code generation and nowhere else

A short answer closes the window in two seconds and nobody notices. A long
tool-using code-generation turn holds it open for minutes — and generating code
is the one activity that reliably makes you edit files, which is what triggers
the reload that destroys the state. The correlation reads as "editing code
breaks the chat"; the truth is that editing code is what you happen to be doing
during the only unprotected window.

HMR is just the cheapest way to reproduce it. A crash, a closed tab, or a
navigation lose the same thing.

## The full-page chat is better off, not immune

`AIChatPage` calls `addMessageToChatResource` with its defaults (`saveChat` and
`persistToServer` both true), so a prompt is persisted when sent. The assistant's
partial reply is still lost, because that half comes from `onFinish` either way.

## Options

1. **Finalize the draft on the user's first message rather than on the first
   assistant reply.** The chat becomes real, gets listed, and survives. Brings
   back some of the clutter the draft rule exists to prevent — though a chat
   holding a real question is not an empty chat, and that is the case that
   matters. Smallest change that fixes the reported symptom.

2. **Persist the assistant message as it streams**, instead of only at
   `onFinish`. Fixes both surfaces, and covers crashes and closed tabs rather
   than only remounts. Costs writes on a hot path — see the write-amplification
   work before assuming this is cheap, and measure rather than guess.

3. **Keep the draft in memory but survive remounts**, by hoisting the in-flight
   state to a module-level map keyed by chat subject — the pattern
   `pendingFirstMessage.ts` already uses for the search-to-chat handoff. No extra
   writes. Fixes HMR only; a crash still loses everything.

**Suggested:** 1 and 3 together. One makes the chat real and listable as soon as
there is something worth keeping; three keeps the streaming reply across a
remount without paying for a write per token. Two is the thorough answer and
should be costed separately, not folded in.

## Worth fixing regardless of which option wins

The loss is silent. Nothing logs, nothing toasts, no commit is dropped — the
resources were never created, so no error path is reached. Whatever the fix, a
conversation vanishing should say so. See
[`silent-failures.md`](./silent-failures.md).
