# Google Calendar import fidelity

Audit: 2026-09-09. Implementation: `codex/calendar-recurring-meetings`, based on
`develop` with the coordinated Google importer prerequisite (`421e4d12f`) and
all-day implementation (`82a6e4460`, cherry-picked here as `19373a6bf`).

## What is implemented

The existing browser-owned OAuth/Syncables importer remains a manual, one-way
import with preview and apply. Atomic edits do not write to Google. Source
identity includes calendar namespace and event ID; identical IDs in two
calendars do not collide. Existing importer reconciliation retains Atomic-only
properties and flags conflicts with local edits.

Two import modes are available:

- **Bounded instances (default):** Google's `singleEvents=true` expands the chosen
  UTC date window. Request `showDeleted=true` to receive available cancellation
  tombstones. This is a snapshot of that window; there are no future generated
  meetings beyond the imported instances.
- **Keep recurring series:** `singleEvents=false`, `showDeleted=true`, no time
  bounds. Fetch all pages of masters and exceptions before preview, subject to
  existing record/response limits. A separate import installation prevents a
  bounded refresh from silently leaving stale masters in a retained-series table.
  Exceptions outside the visible month are needed because they may move an
  original occurrence out of that month. Google documents these list options
  and the conditions affecting deleted events. [Events.list](https://developers.google.com/workspace/calendar/api/v3/reference/events/list)

A JSON projection, `atomic-calendar-recurrence`, retains source calendar identity
and the event's recurrence-relevant fields together. Refresh replaces this whole
projection, so removing a rule does not leave a stale optional rule field active.
The provider's other projected fields remain intact. The catalog adapter supplies
missing `recurrence` and `originalStartTime` schema definitions before parsing;
older catalogs otherwise cause the preview to discard those returned fields.

The month view derives occurrences without creating an unbounded number of
resources. Generated occurrences open their master resource; modified instances
open their exception resource. Recurring chips carry a repeat marker. Editing
source columns alone does not alter the recurrence projection: the JSON
projection is the rendering authority. A dedicated recurrence editor is still
needed (see P1 below).

Supported retained rules: daily, weekly, monthly and yearly frequencies;
`INTERVAL`, `COUNT`, inclusive `UNTIL`, `BYDAY` (including ordinal weekdays),
`BYMONTHDAY`, `BYMONTH`, `BYSETPOS`, `WKST`, multiple rule union, `RDATE`, and
`EXDATE`. Rules expand in their IANA zone using floating wall dates and explicit
instant conversion; exclusions and exceptions match the original instant, not
the changed start. Cancelled masters and instances are hidden. Already-expanded
instances replace matching generated slots. Google's instance identity contract
is `recurringEventId` plus `originalStartTime`, including minimal cancelled
exceptions. [Recurring events](https://developers.google.com/workspace/calendar/api/guides/recurringevents)

Date-only recurrence reuses the separate all-day task's civil-date helpers and
exclusive end projection. All-day occurrences retain their duration in calendar
days through DST. Ordinary all-day creation and range rendering come from that
task, not a second implementation. Google distinguishes date-only ranges from
timed events and defines recurrence as rule/date union minus exclusions.
[Calendar concepts](https://developers.google.com/workspace/calendar/api/concepts/events-calendars)

## Actionable remaining gaps

| Priority | Feature | Current state and next acceptance criterion |
|---|---|---|
| P0 | Larger calendar completeness | Preview limits (5,000 records, response-size limits) reject oversized full-series imports. Add resumable, staged import with explicit completion before making any retained master visible. Never silently truncate exceptions. |
| P0 | Deletions and refresh completeness | Returned tombstones hide meetings, but absence never deletes a resource. Add persisted incremental tokens, all-page staging and recovery from expired tokens. Test delete, restore, cancelled master, cancellation outside old date bounds and interrupted pagination. Google's sync flow requires pagination and a fresh full sync after HTTP 410. [Incremental synchronization](https://developers.google.com/workspace/calendar/api/guides/sync) |
| P1 | Recurrence editor | JSON payloads are editable, but there is no repeat-rule form or “this / this and following / entire series” action. Implement validated controls and series splitting; test changes to title, zone, rule and duration with existing exceptions. Keep one-way Google ownership explicit. |
| P1 | Remaining RFC rules | Full-series mode rejects sub-daily frequencies, BYHOUR/BYMINUTE/BYSECOND, BYYEARDAY, BYWEEKNO, EXRULE and RDATE periods. Use bounded provider expansion for these calendars until supported. Enforce explicit rejection, not a one-off fallback. Engine limits: ≤16 lines/event, ≤2,048 characters/line, ≤100,000 generated candidates/window, ≤10,000 returned occurrences, ≤1-year viewport and series starting in/after 1900 within a 200-year expansion horizon. |
| P1 | Time presentation | Keep actual start/end and zone, but the month grid shows start-day chips, not a timed agenda or duration spans. Add a time label, display-zone selector, week/day views and multi-day timed spans. Validate unusual transitions and historical zones against Google instances. Generated DST gaps are skipped; folds use the earlier instant. Timed duration currently preserves elapsed duration from the master. |
| P1 | All-day integration | Base implementation is reused. Recurring all-day events use `day`, `endDay` (exclusive), `allDay`. Keep bare and `lt-google-calendar-property-…` shortnames compatible. Recheck native creation, import, reload, moved/cancelled all-day exceptions and date-only/timed conversion together. |
| P1 | Metadata preservation | Start/end, title, location, description, status and available participant data pass through the catalog. Audit every provider field against the current catalog, preserve unknown fields in a raw JSON source envelope, and expose loss warnings. Current recurrence projection is not a full archival copy of an event. |
| P1 | Guests and meetings | No native invitation delivery, RSVP workflow, guest permission enforcement, attachment download or conference management. Retaining an attendee or URL field is not equivalent to implementing its behavior. Add field-by-field mapping and dedicated UI; never send invitations as a side effect of import. Google event fields define these structures and permissions. [Event resource](https://developers.google.com/workspace/calendar/api/v3/reference/events) |
| P1 | Reminders and colors | No notification scheduler, effective default-reminder resolution, or calendar-specific color display. Import calendar-list preferences separately from global calendar metadata; test event overrides versus user defaults. [CalendarList](https://developers.google.com/workspace/calendar/api/v3/reference/calendarList) |
| P1 | Privacy and sharing | Import does not recreate Google's ACLs, free/busy access, private-event redaction rules or ownership. Map rights deliberately and show target-drive visibility before import; test reader/freeBusyReader/writer distinctions. [Calendar sharing](https://developers.google.com/workspace/calendar/api/concepts/sharing) |
| P2 | Special event types | Focus time, out of office, working location and birthday semantics need dedicated representation. Do not portray their special automation as an ordinary meeting. Google documents distinct event types and availability constraints. [Event types](https://developers.google.com/workspace/calendar/api/guides/event-types) |
| P2 | Calendar navigation | Imported tables can coexist, but there is no combined multi-calendar agenda with per-calendar visibility/color controls, room availability search or scheduling assistant. Build on retained calendar identities rather than flattening calendars into event names. |

## Available formats and their limits

| Format | Atomic path today | Fidelity and work required |
|---|---|---|
| Google Calendar API via LocalThought | Implemented, authenticated, manually refreshed | Best current path for stable IDs, series and exception identity. Field coverage still depends on the catalog; new recurrence fields are explicitly preserved. API capabilities exceed what the importer currently exposes. |
| Google `.ics` / zipped calendar export | No ICS or ZIP calendar importer | Google exports calendars as ICS, with multiple calendars packaged in a ZIP. Add RFC 5545 parsing, VTIMEZONE handling, UID/RECURRENCE-ID reconciliation, cancellations and multiple-calendar packaging. Preserve civil DATE versus DATE-TIME and exclusive ends. Do not treat API IDs as interchangeable with ICS UIDs. [Google export help](https://support.google.com/calendar/answer/37111?hl=en) |
| CSV | Generic table import is not a faithful calendar migration | No recurrence/exception model is reconstructed from ordinary rows. CSV cannot recover series that were flattened when exported. Google also warns that recurring events imported from CSV may become individual events and that guests/conference data do not import through its file flow. [Google import help](https://support.google.com/calendar/answer/37118?hl=en) |
| JSON-AD | Existing Atomic graph import | Can preserve Atomic recurrence projection and schema when exported together. It is not a parser for Google API event JSON or Google Takeout. |
| Calendar subscriptions / CalDAV | No native calendar subscription/sync path | Requires polling or protocol sync, credentials, deletion handling and ownership rules. The current OAuth import is a manual snapshot, not a live subscription. |

## Verification

Validation on 2026-09-09:

- Shared TypeScript library: **643 tests passed** (90 files), including 19 recurrence tests.
- LocalThought importer: **24 tests passed** (4 files).
- Calendar UI bucketing: **2 tests passed**.
- Rust catalog adapter: **2 tests passed**, compiled as an isolated native module;
  the full native Rust workspace suite was not run.
- Production WASM importer rebuilt successfully with the actual workspace dependencies.
- Frontend and library TypeScript checks passed; changed implementation files pass Oxlint.
- Chromium: **2 import flows passed** (31.5 seconds), covering bounded instances
  and retained series, moved/cancelled slots, all-day ranges, reimport, OPFS reload
  and local-note preservation. Uses the rebuilt WASM and a mock Google provider.

The browser tests retain the existing server-unavailable fixture, including its
expected offline network failures; they are not a production-console cleanliness
check. No real Google account is used. See `TESTING_COVERAGE.md` for test locations.
