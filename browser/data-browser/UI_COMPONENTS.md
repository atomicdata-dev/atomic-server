# Reusable UI Components

Read this before changing UI in the data browser. Prefer these existing primitives over rebuilding layout, overlay, button, loading, resource rendering, or accessibility patterns from scratch.

This list intentionally focuses on components meant to be reused across screens. Feature-specific components in `src/components`, `src/views`, `src/routes`, `src/chunks`, and resource-specific folders are not listed unless they provide a broadly useful UI primitive.

This document might not be entirely up to date. If you need anything that is not listed here, it might still already exist so use your search abilities to look for it first.

**Important:** When you create a new reusable component, add it to this list. Do not add components that are tightly coupled to a specific feature or screen.

## Layout

- `src/components/Main.tsx` - Primary `<main>` landmark with app scroll behavior, print rules, and optional resource view-transition tagging.
- `src/components/Containers.tsx` - Page wrappers: `ContainerNarrow`, `ContainerWide`, and `ContainerFull`, all using shared padding and layout container queries.
- `src/components/Row.tsx` - Contains two of the most important layout components:`Row` and `Column`. These flex layout helpers can build almost any layout.
- `src/components/Gutter.tsx` - Theme-sized vertical spacer for simple layout gaps.
- `src/components/Slot.tsx` - Small grid helper that maps a `slot` prop to `grid-area`, used for slotted layouts such as dialogs.
- `src/components/NavBarSpacer.tsx` - Spacer that accounts for navbar placement and floating behavior.
- `src/helpers/containers.ts` - Shared CSS container names such as `LAYOUT_CONTAINER`, `CARD_CONTAINER`, and `DIALOG_CONTENT_CONTAINER`.

## Surfaces And Sections

- `src/components/Card.tsx` - Standard bordered card surface with optional highlight, nested `Card.Content`, `CardRow`, `CardInsideFull`, and `Margin` helpers.
- `src/components/OutlinedSection.tsx` - Fieldset-style bordered section with an overlapped heading and wrapping row body.
- `src/components/WarningBlock.tsx` - Warning callout with a themed border and `WarningBlock.Title`.
- `src/components/TableList.tsx` - Presentational full-width table for simple row lists, not collection data-grid behavior.

## Disclosure And Navigation UI

- `src/components/Tabs.tsx` - Radix-based tabs with config-driven tab lists, panel children, rounded variant, and error styling.
- `src/components/Collapse.tsx` - Animated expand/collapse wrapper, used in the Details component.
- `src/components/Details.tsx` - Disclosure component similar to `<details>`, with a caret row or custom title control.
- `src/components/ScrollArea.tsx` - Themed Radix scroll area; also exports `ScrollViewPort` for nested viewport needs.
- `src/components/ChatMessagesContainer.tsx` - Stick-to-bottom scroll container for chat-like message lists (auto-scrolls on new content unless the user scrolled up). Used by the AI chat and ChatRoom views.
- `src/components/RightPanel/RightPanel.tsx` - Resizable drawer docked to the right of the screen; combine with `RightPanelContext` so panels (AI sidebar, Comments) are mutually exclusive.

## Resource Views

These components help with rendering resources in different contexts.

- `src/views/ResourceInline/ResourceInline.tsx` - Compact inline link for any resource subject, with loading/error handling and class-specific inline renderers.
- `src/views/ResourceLine.tsx` - Small non-card line item for a resource title and truncated description, useful in dropdowns and dense lists.
- `src/views/Card/ResourceCard.tsx` - Generic card renderer for any resource subject; dispatches to class-specific cards when available and falls back to `ResourceCardDefault`.
  - `src/views/Card/ResourceCardTitle.tsx` - Shared card title row with class icon, resource link, title transition, and optional actions.
- `src/views/ResourcePage.tsx` - Full-page resource view dispatcher that picks the best page component for a resource class and falls back to `ResourcePageDefault`.
- `src/components/EditableTitle.tsx` - Displays the title of a resource as h1 heading with support for editing. Useful on resource pages.

## Dialogs, Popovers, And Menus

- `src/components/Dialog/index.tsx` - Dialog with title/content/action slots. Always use this instead of building your own dialog from scratch. Use in conjunction with `useDialog`
- `src/components/ConfirmationDialog.tsx` - Standard confirm/cancel dialog built on `Dialog`, `useDialog`, and `Button`.
- `src/components/Dropdown/index.tsx` - Menu dropdown with portal rendering, keyboard navigation, dividers, shortcut hints, optional `suffix` metadata, and dialog-tree awareness.
- `src/components/Popover.tsx` - Radix popover wrapper with optional modal behavior, arrow, control locking, and dialog-tree integration.
- `src/components/CustomPopover.tsx` - Lighter popover pattern using local positioning and `usePopover`.

## Buttons, Links, And Selection Controls

- `src/components/Button.tsx` - Core button with default, subtle, alert, icon, clean, gutter, and loading states.
- `src/components/ButtonLink.tsx` - Anchor styled like the default button.
- `src/components/ButtonGroup.tsx` - Mutually exclusive icon-and-label toggle group.
- `src/components/IconButton/IconButton.tsx` - Icon button with multiple visual variants and theme color keys.
- `src/components/SkeletonButton.tsx` - Dashed empty-state button styling, Usually used for actions that create new things.
- `src/components/AtomicLink.tsx` - Atomic Data-aware navigation link for subjects, app paths, or external URLs.
- `src/components/ExternalLink.tsx` - External URL link with plain or button styling and new-window affordance.

## Form controls

- `src/components/forms/Field.tsx` - High level form field skeleton. Pass the actual input as a child component.
- `src/components/forms/Checkbox.tsx` - Themed checkbox input.
- `src/components/forms/RadioInput.tsx` - Themed radio input.
- `src/components/forms/SliderInput.tsx` - Themed range input.
- `src/components/forms/MarkdownInput.tsx` - Themed markdown input.
- `src/components/forms/EmojiInput.tsx` - Themed emoji input.
- `src/components/ComboBox.tsx` - Filterable combobox using Downshift and QuickScore, with optional CSS anchor positioning.

**Note**: When rendering inputs for resource values, use `src/components/forms/InputSwitcher.tsx` to render the appropriate input based on the property's datatype.

## Feedback, Loading, And Content Blocks

- `src/components/Loader.tsx` - `LoaderInline` and `LoaderBlock` skeleton pulse placeholders.
- `src/components/Shimmer.tsx` - Wrapper that sweeps a highlight over visible children while a process is loading or running; toggle with `active`.
- `src/components/Spinner.tsx` - Circular SVG loading indicator.
- `src/components/ProgressBar.tsx` - Theme-styled `<progress>` element.
- `src/components/CodeBlock.tsx` - Code `<pre>` wrapper with a copy button and toast feedback.
- `src/components/HighlightedCodeBlock.tsx` - Lazy-loaded syntax-highlighted code block boundary.
- `src/components/ErrorLook.tsx` - Shared error typography, simple error box, and `ErrorBlock` with optional trace details.
- `src/components/CommentCountBadge.tsx` - Live comment-count pill for any resource (counts Messages whose `about` points at it); highlights when there are unseen messages (device-local, via `useLastSeenComments`).
- `src/components/Presence/ResourcePresenceRow.tsx` - Facepile of agents currently viewing a resource (ephemeral drive presence); also announces the viewer's own presence. Skips the currently-followed agent (their avatar lives in the navbar's Following badge).
- `src/components/Presence/AgentAvatar.tsx` - Round agent avatar: profile image (`image` File prop or `imageUrl`) with colored-initial fallback; any size. Exports `colorForAgent` for a stable per-agent color on any presence surface.
- `src/components/Presence/SidebarPresence.tsx` - Compact read-only avatar strip for sidebar rows showing who is currently at that resource.

## Accessibility And Input Affordances

- `src/components/VisuallyHidden.ts` - Visually hidden wrapper that remains available to screen readers.
- `src/components/HideInPrint.tsx` - Wrapper that renders normally on screen and hides children in print, used to hide unwanted elements when exporting documents to PDF.
- `src/components/Shortcut.tsx` - Renders keyboard shortcut strings as styled `<kbd>` segments.

## Theme, Motion, And Styling Helpers

- `src/styling.tsx` - Theme wrapper, design tokens, `size()` spacing scale, z-index scale, and global styles.
- `src/helpers/transition.ts` - Standard transition helper using the theme animation duration.
- `src/helpers/commonAnimations.ts` - Shared keyframes such as `fadeIn`.
- `src/helpers/CSSVar.ts` - Helper for creating and using css variables.
- `src/globalCssVars.ts` - Typed CSS variable helpers used by layout and global surfaces.

- `src/components/TeamProfileStep.tsx` — shared collaboration profile review for senders and invitees. Saves full name and optional cropped avatar to the existing Atomic agent before continuing; requires no SaaS account.
