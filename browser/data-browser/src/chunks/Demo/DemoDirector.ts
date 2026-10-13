// @wc-ignore-file
// (Wuchale: scripted demo dialogue, not app chrome — the injected
// translation-loader hook would throw outside React anyway.)
'use no memo';
import {
  StoreEvents,
  commits,
  core,
  dataBrowser,
  type PresenceEntry,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  PERSONAS,
  ROW_DOODLE,
  ROW_EXPLORE_BOARD,
  ROW_SAY_HI,
  createDemoMessage,
  type ChecklistStatus,
  type DemoManifest,
  type PersonaKey,
} from './demoWorkspace';
import { colorForAgent } from '../../components/Presence/AgentAvatar';
import { simulatePropEdit } from './simulatedEdits';
import { isFollowEntry } from '../../helpers/chatLog';
import { SimulatedTypist } from './SimulatedTypist';
import { greetingFor } from './greeting';
import { YUSUF_LIVE_STROKES } from './moodboardStrokes';

/** Presence entries expire after 30s; refresh well inside that. */
const HEARTBEAT_MS = 10_000;
/** Base delay between typed characters; jittered per character, with an
 *  extra beat at word boundaries so the rhythm reads as human typing. Slow
 *  enough to read along: at 35 ms the first lines raced past before a new
 *  visitor had found them. */
const LETTER_MS = 50;
/** A breath between tour stops, so a page change never lands mid-sentence. */
const STEP_PAUSE_MS = 2_500;
/** How often Yusuf's canvas cursor moves while he's idling on the
 *  moodboard. Short enough that the dot glides instead of hopping. */
const WANDER_TICK_MS = 120;
/** The patch of canvas world space Yusuf's cursor stays inside — the
 *  area the moodboard artwork occupies. */
const WANDER_BOUNDS = { minX: 60, maxX: 900, minY: 60, maxY: 600 };

interface PersonaState {
  sessionId: string;
  /** Present = has an entry; absent = left (or not yet joined). */
  entry?: PresenceEntry;
}

/**
 * Plays the "Your first day" scenario (`planning/demo-experience.md`):
 * scripted teammates join the demo drive's presence channel, type into
 * the welcome doc, work the launch board, and wind down — while the
 * user is free to edit everything they touch.
 *
 * All state changes go through `applyIncoming` (simulated remote
 * peers); all awareness goes through `DrivePresenceManager.injectEntry`.
 * The run loop pauses while the tab is hidden so the user doesn't miss
 * the show, and every beat re-checks the resources it touches so a
 * user who deleted something is skipped over gracefully.
 *
 * Meeting: Mara starts a tour Meeting (drive `currentMeetings` + her
 * presence `session`), which lights up the top-bar Join banner. She
 * narrates each stop in the meeting chat and posts "Viewing …" trail
 * entries as she moves; the board's cards are the tour steps, so she
 * literally drags "Explore the kanban board" to Done while there.
 */
export class DemoDirector {
  private stopped = false;
  private started = false;
  /** Guards the reactive user-edit trigger against our own saves. */
  private selfSaving = false;
  /**
   * Subjects the director recently pushed deltas into, with timestamps.
   * An open editor re-saves imported remote ops (its debounced
   * save-on-change fires for persona edits too), which would satisfy
   * the "user edited something" trigger seconds after Mara types. A
   * save that lands right after we touched the same subject is that
   * echo, not the user.
   */
  private recentlyTouched = new Map<string, number>();
  private maraFollowed = false;
  /** The tour Meeting, created live once Mara "starts" it. */
  private meeting?: string;
  private userChatted = false;
  private userChatWaiters: Array<() => void> = [];
  /** The user's own Team-table row (guest DID or a created row), set at the
   *  team-table tour stop — the checkbox `completeSayHi` ticks. */
  private memberRow?: string;
  /** Mara's answer to the user's first message, memoized so it runs at most
   *  once no matter whether the linear script or the reactive chat listener
   *  triggers it first — and so the script's `await` joins the listener's
   *  in-flight run instead of racing ahead of it. */
  private greetPromise?: Promise<void>;
  /** Mara has brought the user to the board, where the "Say hi" card lives. */
  private onBoard = false;
  private sayHiCardMoved = false;
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private wanderTimer?: ReturnType<typeof setInterval>;
  private tableWanderTimer?: ReturnType<typeof setInterval>;
  /** Yusuf's cursor position in canvas world coordinates. Shared by the
   *  idle wander and the stroke-tracing beat, so the two hand over
   *  without the cursor teleporting. */
  private yusufPointer = { x: 420, y: 260 };
  /** Set while Yusuf traces a stroke, so the wander timer keeps its
   *  hands off the cursor. */
  private yusufDrawing = false;
  private unsubscribePresence?: () => void;
  private unsubscribeSaved?: () => void;
  private personas: Record<PersonaKey, PersonaState>;
  private startWhen: Promise<void> = Promise.resolve();

  public constructor(
    private store: Store,
    private manifest: DemoManifest,
  ) {
    this.personas = {
      mara: { sessionId: 'demo-session-mara' },
      yusuf: { sessionId: 'demo-session-yusuf' },
      pip: { sessionId: 'demo-session-pip' },
    };
  }

  /** @param when Resolves when the scenario may begin; immediately if absent. */
  public start(when: Promise<void> = Promise.resolve()): void {
    if (this.started) return;
    this.started = true;
    this.startWhen = when;

    // Keep the presence manager alive for the whole scenario, even
    // while no presence-consuming UI is mounted — and watch for the
    // user starting to follow Mara.
    this.unsubscribePresence = this.store
      .getPresence(this.manifest.drive)
      .subscribe(() => this.onPresenceChange());

    this.unsubscribeSaved = this.store.on(
      StoreEvents.ResourceSaved,
      resource => {
        if (!this.store.isLocalOnlySubject(resource.subject)) return;

        // The reactive trigger: a message the user posted into the meeting
        // chat ("say something"). A message is an entry in a page of the
        // meeting's chat log. Only something the user typed counts: joining
        // the meeting and following Mara also post entries here, as the user
        // ("Demo User joined the meeting", "Viewing …"), but those are
        // follow events; a persona's line is authored as the persona. That
        // author check is what tells the user's line from ours, so this must
        // NOT be gated on `selfSaving`: that flag is raised for the whole
        // duration of each of our own saves, and a message the user sent
        // inside such a window was dropped, leaving the chat unanswered.
        if (
          this.meeting &&
          resource.get(core.properties.parent) === this.meeting &&
          resource.hasClasses(dataBrowser.classes.chatLog) &&
          this.userTyped(resource)
        ) {
          this.userChatted = true;
          this.userChatWaiters.forEach(resolve => resolve());
          this.userChatWaiters = [];
          // Answer reactively — so Mara replies the moment the user chats,
          // even outside the script's wait window (e.g. they explored first).
          void this.completeSayHi();
        }
      },
    );

    this.heartbeatTimer = setInterval(
      () => this.refreshPresence(),
      HEARTBEAT_MS,
    );

    void this.run().catch(e => {
      console.warn('[Demo] director stopped on error:', e);
      this.stop();
    });
  }

  /** Whether the chat log page holds a line the signed-in user typed. */
  private userTyped(page: Resource): boolean {
    const me = this.store.getAgent()?.subject;

    return (
      !!me &&
      page
        .listChatLogEntries()
        .some(({ entry }) => entry.a === me && !isFollowEntry(entry))
    );
  }

  public stop(): void {
    if (this.stopped) return;
    this.stopped = true;

    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.wanderTimer) clearInterval(this.wanderTimer);
    this.stopTableWander();

    const manager = this.store.getPresence(this.manifest.drive);

    for (const persona of Object.values(this.personas)) {
      if (persona.entry) manager.removeEntry(persona.sessionId);
      persona.entry = undefined;
    }

    this.unsubscribeSaved?.();
    this.unsubscribePresence?.();
    // Resolve any waiter so an in-flight `run()` unblocks and exits.
    this.userChatWaiters.forEach(resolve => resolve());
    this.userChatWaiters = [];
    void this.endTourMeeting();
  }

  // ─── The scenario ────────────────────────────────────────────────

  private async run(): Promise<void> {
    const { manifest } = this;

    await this.startWhen;
    if (this.stopped) return;

    // The user lands in the onboarding meeting (see `DemoRoute`). Starting it
    // lists it as live and puts Mara in it, which is what opens the meeting
    // chat beside them: opening a live meeting is joining it.
    await this.startTourMeeting();
    if (this.stopped) return;

    this.announceMara(manifest.meeting);
    this.announce('yusuf', { resource: manifest.moodboard });
    this.startYusufWander();

    // The meeting notes are being written as the meeting starts; the user
    // reads along while Mara talks in the chat.
    const notes = this.type('mara', manifest.meeting, [
      'This workspace is a demo of atomic.place.',
      'Feel free to edit, remove or create anything you like!',
    ]).catch(() => undefined);

    // Give the chat panel a moment to open. If they don't join within a few
    // seconds, carry on anyway so the log exists for whenever they do.
    await this.waitForJoin(8_000);

    if (this.stopped) return;

    await this.narrate(
      'Welcome to atomic.place! 👋 I’m Mara, glad you’re here.',
    );
    await this.narrate(
      'First things first: say hi in this chat. I’ll show you the rest of the workspace after that.',
    );

    // Nothing changes page until they have said hi (or a while has passed),
    // so they are never mid-sentence in the chat when the page moves.
    const saidHi = await this.waitForUserChat(45_000);

    if (this.stopped) return;

    if (saidHi) {
      await this.completeSayHi();
    } else {
      await this.narrate(
        'No rush, say hi whenever you like. Let’s have a look around.',
      );
    }

    if (this.stopped) return;

    await notes;
    await this.sleep(STEP_PAUSE_MS);
    // Call out the Meeting feature itself while we're in one.
    await this.narrate(
      'This is a Meeting 🎥. Anyone on the team can start one to chat with colleagues and look at the same thing at the same time.',
    );
    await this.narrate(
      'You’re following me right now, so we’re looking at the same thing. Come along, I’ll walk you through the rest.',
    );
    await this.sleep(STEP_PAUSE_MS);

    // Mara moves to the board and the user follows. Their first task is
    // waiting there: if they said hi, it ticks off in front of them.
    this.announceMara(manifest.checklist.table, {
      row: manifest.checklist.rows[ROW_SAY_HI],
      column: manifest.checklist.statusColumn,
    });
    this.onBoard = true;
    await this.sleep(STEP_PAUSE_MS);
    await this.tickSayHiCard();

    // ── Tour stop 1: the board (the long, lively, meta stop) ──
    this.announceMara(manifest.checklist.table, {
      row: manifest.checklist.rows[ROW_EXPLORE_BOARD],
      column: manifest.checklist.statusColumn,
    });
    await this.narrate('First stop: the board. A tool to keep track of todos!');
    await this.sleep(700);
    await this.narrate(
      'Watch — I’ll move “Explore the kanban board” to doing.',
    );
    await this.sleep(800);
    await this.moveCard(
      'mara',
      manifest.checklist.rows[ROW_EXPLORE_BOARD],
      'Doing',
    );
    await this.sleep(800);
    await this.moveCard(
      'mara',
      manifest.checklist.rows[ROW_EXPLORE_BOARD],
      'Done',
    );
    await this.narrate('✅ one down.');

    // Pip joins and adds a brand-new card, live.
    this.announce('pip', {
      resource: manifest.checklist.table,
      data: {
        row: manifest.checklist.rows[ROW_SAY_HI],
        column: manifest.checklist.statusColumn,
      },
    });
    await this.sleep(1_500);
    await this.postChat('pip', "ooh a new teammate, I'll add a card👋");
    await this.addChecklistCard('Invite the rest of your team', 'Todo');
    await this.narrate("Next: the moodboard, Yusuf's mid-doodle 🎨");
    await this.sleep(STEP_PAUSE_MS);

    // ── Tour stop 2: the moodboard, Yusuf drawing live ──
    this.announceMara(manifest.moodboard, { x: 340, y: 220 });
    void this.yusufFinishesTheFace();
    await this.sleep(7_000);
    await this.moveCard('mara', manifest.checklist.rows[ROW_DOODLE], 'Done');
    await this.narrate('And that ticks off “Doodle on the moodboard” ✅');
    await this.narrate('One more stop: the Team table.');
    await this.sleep(STEP_PAUSE_MS);

    // ── Tour stop 3: the team table — the user becomes a row in it ──
    this.announceMara(manifest.team.table);
    this.startTableWander();
    await this.narrate('This is where we keep track of our members!');
    await this.narrate(
      'Tables in atomic.place are pretty powerful, you can define custom columns, filters and views.',
    );
    await this.sleep(1_500);
    await this.narrate(
      "But you're still missing in the Team table, adding you to the roster ✍️",
    );

    const memberRow = await this.ensureTeamRow();
    this.memberRow = memberRow;

    if (memberRow && !this.stopped) {
      // Mara's presence sits on the new member's Role cell while she
      // fills it in — the same cell ring a real collaborator would cast.
      this.announceMara(manifest.team.table, {
        row: memberRow,
        column: manifest.team.roleColumn,
      });
      await this.sleep(1_200);

      const rowResource = await this.getBeatResource(memberRow);

      if (rowResource) {
        this.touch(memberRow);
        await simulatePropEdit(
          this.store,
          rowResource,
          manifest.personas.mara,
          properties => {
            properties.set(manifest.team.roleColumn, 'Newest teammate 🎉');
            // They said hi at the start, before this row existed, so the
            // say-hi payoff could not tick it then.
            if (this.userChatted)
              properties.set(manifest.team.onboardingColumn, true);
          },
        );
      }

      await this.narrate('There — “Meet the team” is officially done ✅');
    }

    await this.sleep(3_000);
    this.stopTableWander();

    // ── The ask, only if they skipped it at the start ──
    this.announceMara(manifest.checklist.table);

    if (!this.userChatted) {
      await this.narrate(
        'Last step 👇 say hi in this chat. That’ll tick off “Say hi in the meeting chat” for you.',
      );

      // Don't wind down until the user has actually said hi: ending the
      // meeting first leaves them chatting into a dead room. The reactive
      // listener also fires `completeSayHi` the moment they chat.
      const chatted = await this.waitForUserChat(4 * 60_000);

      if (this.stopped) return;
      if (chatted) await this.completeSayHi();
    }

    await this.sleep(6_000);

    // Wind-down: end the meeting, team leaves one by one.
    await this.narrate('That’s the tour — the workspace is all yours now. 🚀');
    await this.endTourMeeting();

    this.leave('yusuf');
    await this.sleep(4_000);
    await this.postChat('pip', 'calling it — launch is tomorrow 🚀');
    this.leave('pip');
    await this.sleep(4_000);

    await this.type('mara', manifest.welcomeDoc, [
      'Everything here is editable, deletable, yours. Poke around!',
    ]);
    await this.sleep(2_000);
    this.leave('mara');
  }

  // ─── Presence ────────────────────────────────────────────────────

  /** Mara's announces carry `allowFollow` plus, once the tour meeting
   *  starts, its subject as `session` — so joiners open the meeting
   *  chat. Posts a "Viewing …" trail entry into the meeting as she
   *  moves. */
  private announceMara(resource: string, data?: unknown): void {
    const moved = this.personas.mara.entry?.resource !== resource;

    this.announce('mara', {
      resource,
      allowFollow: true,
      session: this.meeting,
      ...(data !== undefined ? { data } : {}),
    });

    // While the meeting is live, log each stop as a trail entry. The meeting
    // itself is not a stop: it is where the trail is kept.
    if (moved && this.meeting && resource !== this.meeting) {
      void this.postTrail(viewingMessage(this.store, resource));
    }
  }

  private announce(key: PersonaKey, entry: Omit<PresenceEntry, 'agent'>): void {
    if (this.stopped) return;
    const persona = this.personas[key];
    persona.entry = { ...entry, agent: this.manifest.personas[key] };
    this.store
      .getPresence(this.manifest.drive)
      .injectEntry(persona.sessionId, persona.entry);
  }

  /** Toggle Mara's "typing…" presence in the meeting chat, so the demo shows
   *  the same live indicator a real teammate produces while composing. Keyed on
   *  the meeting subject, which is the chat thread the panel announces. */
  private setMaraTyping(on: boolean): void {
    const entry = this.personas.mara.entry;

    if (!entry || !this.meeting) return;

    this.personas.mara.entry = {
      ...entry,
      typing: on ? this.meeting : undefined,
    };
    this.store
      .getPresence(this.manifest.drive)
      .injectEntry(this.personas.mara.sessionId, this.personas.mara.entry);
  }

  private leave(key: PersonaKey): void {
    const persona = this.personas[key];
    persona.entry = undefined;
    this.store.getPresence(this.manifest.drive).removeEntry(persona.sessionId);
  }

  private refreshPresence(): void {
    if (this.stopped) return;
    const manager = this.store.getPresence(this.manifest.drive);

    for (const persona of Object.values(this.personas)) {
      if (persona.entry) {
        manager.injectEntry(persona.sessionId, persona.entry);
      }
    }
  }

  /** Track whether the user has joined (their presence follows Mara),
   *  which gates the tour beat. */
  private onPresenceChange(): void {
    if (this.stopped) return;

    const snapshot = this.store.getPresence(this.manifest.drive).getSnapshot();
    this.maraFollowed = snapshot.some(
      item =>
        !item.sessionId.startsWith('demo-session-') &&
        item.following === this.manifest.personas.mara,
    );
  }

  /** Broadcast Yusuf's canvas pointer, as long as he's still looking at
   *  the moodboard. */
  private moveYusufPointer(x: number, y: number): void {
    const yusuf = this.personas.yusuf;

    if (
      this.stopped ||
      !yusuf.entry ||
      yusuf.entry.resource !== this.manifest.moodboard
    ) {
      return;
    }

    this.yusufPointer = { x, y };

    this.announce('yusuf', {
      ...yusuf.entry,
      data: { x: Math.round(x), y: Math.round(y) },
    });
  }

  /** Travel the cursor to a point over a few frames, so reaching for the
   *  next stroke reads as a hand moving rather than a jump cut. */
  private async glideYusufTo(x: number, y: number): Promise<void> {
    const from = { ...this.yusufPointer };
    const steps = 8;

    for (let i = 1; i <= steps; i++) {
      if (this.stopped) return;

      const t = i / steps;
      // Ease out, so the cursor arrives gently instead of slamming.
      const eased = 1 - (1 - t) * (1 - t);

      this.moveYusufPointer(
        from.x + (x - from.x) * eased,
        from.y + (y - from.y) * eased,
      );
      await this.sleep(40);
    }
  }

  /** Yusuf's cursor drifts around the moodboard while he's on it —
   *  a smooth random walk in canvas world coordinates. */
  private startYusufWander(): void {
    let vx = 6;
    let vy = 4;

    this.wanderTimer = setInterval(() => {
      const yusuf = this.personas.yusuf;

      if (
        this.stopped ||
        this.yusufDrawing ||
        !yusuf.entry ||
        yusuf.entry.resource !== this.manifest.moodboard ||
        document.hidden
      ) {
        return;
      }

      vx += (Math.random() - 0.5) * 5;
      vy += (Math.random() - 0.5) * 5;
      vx = Math.max(-10, Math.min(10, vx));
      vy = Math.max(-10, Math.min(10, vy));

      let x = this.yusufPointer.x + vx;
      let y = this.yusufPointer.y + vy;

      // Bounce off the edges. Clamping alone parks the cursor against a
      // border for as long as the velocity keeps pointing outward, which
      // reads as a frozen, and so invisible, collaborator.
      if (x < WANDER_BOUNDS.minX || x > WANDER_BOUNDS.maxX) {
        vx = -vx;
        x = Math.max(WANDER_BOUNDS.minX, Math.min(WANDER_BOUNDS.maxX, x));
      }

      if (y < WANDER_BOUNDS.minY || y > WANDER_BOUNDS.maxY) {
        vy = -vy;
        y = Math.max(WANDER_BOUNDS.minY, Math.min(WANDER_BOUNDS.maxY, y));
      }

      this.moveYusufPointer(x, y);
    }, WANDER_TICK_MS);
  }

  /** Pip reads through the Team table while the tour is parked there:
   *  her selected cell hops from cell to cell, so the table shows a
   *  teammate at work rather than a still frame. */
  private startTableWander(): void {
    const { team, personas } = this.manifest;
    const columns = [
      team.roleColumn,
      team.responsibilitiesColumn,
      team.doingTaskColumn,
      team.onboardingColumn,
    ];
    const rows = [personas.pip, personas.yusuf, personas.mara];
    let index = 0;

    this.tableWanderTimer = setInterval(() => {
      if (this.stopped || document.hidden) return;

      // Walk the grid cell by cell, wrapping — a steady reading motion
      // reads better on camera than a random jitter.
      index = (index + 1) % (rows.length * columns.length);

      this.announce('pip', {
        resource: team.table,
        data: {
          row: rows[Math.floor(index / columns.length)],
          column: columns[index % columns.length],
        },
      });
    }, 900);
  }

  private stopTableWander(): void {
    if (this.tableWanderTimer) {
      clearInterval(this.tableWanderTimer);
      this.tableWanderTimer = undefined;
    }
  }

  // ─── State changes (simulated remote peers) ──────────────────────

  /** A beat's resource lookup must never kill the scenario: deleted or
   *  unresolvable resources (getResource can reject) just skip the beat. */
  private async getBeatResource(subject: string) {
    try {
      const resource = await this.store.getResource(subject);

      return resource.error ? undefined : resource;
    } catch {
      return undefined;
    }
  }

  /**
   * `newResource` reads the parent's drive from memory. A parent that is not
   * loaded makes the child claim the parent itself as its drive, so the store
   * no longer sees it as local-only and posts its genesis to the server, which
   * answers 404 on every outbox retry. Load the parent (from the local
   * database) first, and refuse to create under one that is really gone.
   *
   * A local-only subject can only be read once the local database has opened,
   * and that can still be underway while the demo starts. Wait for it, and when
   * it never opens, carry on as before rather than failing the demo on a
   * read that could not have succeeded.
   */
  private async loadParent(subject: string): Promise<void> {
    const dbReady = (await this.store.getClientDb()?.waitForReady()) ?? false;
    const parent = await this.store.getResource(subject).catch(() => undefined);

    if (parent && !parent.error) return;
    if (!dbReady) return;

    throw new Error(`Demo parent ${subject} is not in the local demo drive`);
  }

  private touch(subject: string): void {
    this.recentlyTouched.set(subject, Date.now());
  }

  /** The in-document caret identity: same name + deterministic color
   *  as the persona's avatar everywhere else. */
  private cursorUser(key: PersonaKey): { name: string; color: string } {
    return {
      name: PERSONAS[key].name,
      color: colorForAgent(this.manifest.personas[key]),
    };
  }

  /** Type `text` into the doc letter by letter, like a person would —
   *  each character lands as its own remote edit, with a jittered
   *  keystroke delay and a brief hesitation after each word. */
  private async typeText(
    typist: SimulatedTypist,
    docSubject: string,
    text: string,
  ): Promise<void> {
    // Array.from splits by code point, so multi-unit characters
    // (emoji, — ) land whole instead of as broken surrogate halves.
    for (const letter of Array.from(text)) {
      if (this.stopped) return;
      this.touch(docSubject);
      typist.appendText(letter);

      const wordBoundary = /\s/.test(letter) ? Math.random() * 130 : 0;
      await this.sleep(LETTER_MS + Math.random() * 40 + wordBoundary);
    }
  }

  /** Type paragraphs into a document, letter by letter. Skips silently
   *  if the user deleted the doc. */
  private async type(
    key: PersonaKey,
    docSubject: string,
    paragraphs: string[],
  ): Promise<void> {
    const resource = await this.getBeatResource(docSubject);

    if (!resource) return;

    // The typist reads as "someone is in this doc" — move the persona
    // there if they aren't already.
    const persona = this.personas[key];

    if (persona.entry && persona.entry.resource !== docSubject) {
      this.announce(key, { ...persona.entry, resource: docSubject });
    }

    const typist = new SimulatedTypist(
      this.store,
      resource,
      this.manifest.personas[key],
      this.cursorUser(key),
    );

    try {
      await typist.start();

      for (const paragraph of paragraphs) {
        if (this.stopped) return;
        this.touch(docSubject);
        typist.appendParagraph();

        await this.typeText(typist, docSubject, paragraph);

        if (this.stopped) return;

        // A beat between paragraphs, not after the last: whatever comes next
        // (the meeting invite) should follow without a gap.
        if (paragraph !== paragraphs[paragraphs.length - 1])
          await this.sleep(500);
      }
    } finally {
      typist.stop();
    }
  }

  /** Move a board card to a status column (kanban) as a persona. The
   *  persona "picks the card up" first — a dragging presence beat that
   *  makes the card pulse on every open board — then drops it with the
   *  status edit. */
  private async moveCard(
    key: PersonaKey,
    rowSubject: string,
    status: ChecklistStatus,
  ): Promise<void> {
    const row = await this.getBeatResource(rowSubject);
    const tag = this.manifest.checklist.statusTags[status];

    if (!row || !tag) return;

    this.announce(key, {
      ...this.personas[key].entry,
      resource: this.manifest.checklist.table,
      data: { row: rowSubject, dragging: true },
    });
    await this.sleep(1_200);

    if (this.stopped) return;

    this.touch(rowSubject);
    await simulatePropEdit(
      this.store,
      row,
      this.manifest.personas[key],
      properties => properties.set(this.manifest.checklist.statusColumn, [tag]),
    );

    // Dropped: presence stays on the card, no longer dragging.
    this.announce(key, {
      ...this.personas[key].entry,
      resource: this.manifest.checklist.table,
      data: { row: rowSubject },
    });
  }

  /** Mara's answer to the user's first message: greet them by name, and tick
   *  their onboarding checkbox when their Team-table row exists. Idempotent
   *  and callable from either the linear script or the reactive chat
   *  listener, whichever sees the message first. Best-effort throughout (a
   *  missing meeting just skips the chatter). The "Say hi" card is ticked
   *  separately, once Mara has brought the user to the board. */
  private completeSayHi(): Promise<void> {
    if (!this.greetPromise) {
      this.greetPromise = this.runSayHi();
    }

    return this.greetPromise;
  }

  private async runSayHi(): Promise<void> {
    if (this.stopped) return;

    // A direct, prompt reply: this is an answer to what they just typed.
    await this.narrate(greetingFor(await this.userName()), { reply: true });
    await this.postChat('yusuf', 'the new teammate speaks 🎉');

    // Tick their "Completed onboarding" checkbox — Mara flips it, the same
    // as a real teammate marking your onboarding done.
    if (this.memberRow) {
      const rowResource = await this.getBeatResource(this.memberRow);

      if (rowResource) {
        try {
          this.touch(this.memberRow);
          await simulatePropEdit(
            this.store,
            rowResource,
            this.manifest.personas.mara,
            properties =>
              properties.set(this.manifest.team.onboardingColumn, true),
          );
        } catch (e) {
          console.warn('[Demo] could not tick onboarding checkbox:', e);
        }
      }
    }

    // They said hi after Mara had already moved on to the board.
    await this.tickSayHiCard();
  }

  /** Drag "Say hi in the meeting chat" to Done, once the user has said hi and
   *  Mara has brought them to the board. At most once. */
  private async tickSayHiCard(): Promise<void> {
    if (this.sayHiCardMoved || !this.userChatted || !this.onBoard) return;
    this.sayHiCardMoved = true;

    await this.moveCard(
      'mara',
      this.manifest.checklist.rows[ROW_SAY_HI],
      'Done',
    );
  }

  /** The signed-in user's display name, if their agent has one. */
  private async userName(): Promise<string | undefined> {
    const subject = this.store.getAgent()?.subject;

    if (!subject) return undefined;

    const agent = await this.getBeatResource(subject);

    return agent?.title;
  }

  /** Yusuf draws the second creature's face onto the moodboard, one
   *  stroke at a time (the body shipped with the template). */
  private async yusufFinishesTheFace(): Promise<void> {
    const moodboard = await this.getBeatResource(this.manifest.moodboard);

    if (!moodboard) return;

    const strokeDataProp = 'https://atomicdata.dev/ontology/canvas/strokeData';

    this.yusufDrawing = true;

    try {
      for (const stroke of YUSUF_LIVE_STROKES) {
        if (this.stopped) return;

        const path = stroke.path as [number, number][];
        const [startX, startY] = path[0] ?? [
          this.yusufPointer.x,
          this.yusufPointer.y,
        ];

        // Reach for the start of the stroke, then draw it: the cursor has
        // to be where the ink appears, or the drawing looks unattended.
        await this.glideYusufTo(startX, startY);
        await this.sleep(120);

        for (const [pointX, pointY] of path) {
          if (this.stopped) return;
          this.moveYusufPointer(pointX, pointY);
          await this.sleep(45);
        }

        const current = moodboard.get(strokeDataProp);
        const strokes = Array.isArray(current) ? [...current] : [];
        strokes.push(stroke as unknown as (typeof strokes)[number]);

        this.touch(this.manifest.moodboard);
        await simulatePropEdit(
          this.store,
          moodboard,
          this.manifest.personas.yusuf,
          properties => properties.set(strokeDataProp, strokes),
        );

        await this.sleep(150 + Math.random() * 200);
      }
    } finally {
      this.yusufDrawing = false;
    }
  }

  /** The user's row in the Team table: a guest's profile row (guest
   *  agents are created WITH one, subject = their agent DID), else a
   *  fresh member row named after their agent. Like `addChecklistCard`,
   *  a new row needs a user-signed genesis commit. */
  private async ensureTeamRow(): Promise<string | undefined> {
    const { team } = this.manifest;
    const agentSubject = this.store.getAgent()?.subject;

    if (agentSubject) {
      const profile = this.store.getResourceLoading(agentSubject);

      if (profile.get(core.properties.parent) === team.table) {
        return agentSubject;
      }
    }

    this.selfSaving = true;

    try {
      const agent = agentSubject
        ? await this.store.getResource(agentSubject)
        : undefined;
      await this.loadParent(team.table);
      const row = await this.store.newResource({
        parent: team.table,
        isA: team.rowClass,
        propVals: {
          [core.properties.name]: agent?.title ?? 'New teammate',
          [team.roleColumn]: 'New teammate',
          // First day — not onboarded yet; `completeSayHi` ticks this.
          [team.onboardingColumn]: false,
          // Latest createdAt → the ascending default sort lands it last.
          [commits.properties.createdAt]: Date.now(),
        },
      });
      await row.save();
      // A local save alone doesn't refresh open collections (only a server
      // UPDATE push or this call does), so the Team table wouldn't show the
      // new row live — it'd appear only on re-navigation. Nudge it.
      await this.store.notifyResourceManuallyCreated(row);

      return row.subject;
    } catch (e) {
      console.warn('[Demo] could not add the user to the team table:', e);

      return undefined;
    } finally {
      this.selfSaving = false;
    }
  }

  /** New cards need a genesis commit, which only the user's agent can
   *  sign — so this one beat is authored by the user, guarded against
   *  the reactive edit trigger. */
  private async addChecklistCard(
    name: string,
    status: ChecklistStatus = 'Todo',
  ): Promise<string | undefined> {
    this.selfSaving = true;

    try {
      const tag = this.manifest.checklist.statusTags[status];
      await this.loadParent(this.manifest.checklist.table);
      const card = await this.store.newResource({
        parent: this.manifest.checklist.table,
        isA: this.manifest.checklist.rowClass,
        propVals: {
          [core.properties.name]: name,
          [this.manifest.checklist.statusColumn]: tag ? [tag] : [],
          [commits.properties.createdAt]: Date.now(),
        },
      });
      await card.save();
      // Same as the team row: make the board pick up the card live rather
      // than only after the collection is rebuilt on re-navigation.
      await this.store.notifyResourceManuallyCreated(card);

      return card.subject;
    } catch (e) {
      console.warn('[Demo] could not add board card:', e);

      return undefined;
    } finally {
      this.selfSaving = false;
    }
  }

  /** Persona-authored message in the Team chat. */
  private async postChat(key: PersonaKey, text: string): Promise<void> {
    if (this.stopped) return;
    this.selfSaving = true;

    try {
      await createDemoMessage(this.store, {
        parent: this.manifest.teamChat,
        author: this.manifest.personas[key],
        text,
      });
    } catch (e) {
      console.warn('[Demo] could not post chat message:', e);
    } finally {
      this.selfSaving = false;
    }
  }

  /** Mara-authored meeting trail entry (a "Viewing …" event). */
  private async postTrail(text: string): Promise<void> {
    if (this.stopped || !this.meeting) return;
    this.selfSaving = true;

    try {
      await createDemoMessage(this.store, {
        parent: this.meeting,
        author: this.manifest.personas.mara,
        text,
        extraClasses: [dataBrowser.classes.followEvent],
      });
    } catch (e) {
      console.warn('[Demo] could not post meeting trail:', e);
    } finally {
      this.selfSaving = false;
    }
  }

  /** Mara-authored narration in the meeting chat (a regular message,
   *  so it reads as speech, not a system event). Posts after a
   *  length-proportional compose pause — a beat to think, then typing
   *  time — so back-to-back narration paces like a person chatting
   *  instead of a script dumping lines. */
  private async narrate(
    text: string,
    { reply = false }: { reply?: boolean } = {},
  ): Promise<void> {
    if (this.stopped || !this.meeting) return;

    // Show "Mara is typing…" while she composes, then clear it as she sends.
    // A reply to something the user just typed composes quickly and does not
    // wait for the tab to be visible: it must land when they expect it.
    this.setMaraTyping(true);
    await (reply
      ? this.sleep(500 + Math.random() * 300, { pauseWhenHidden: false })
      : this.sleep(700 + text.length * 40 + Math.random() * 500));
    this.setMaraTyping(false);

    if (this.stopped || !this.meeting) return;
    this.selfSaving = true;

    try {
      await createDemoMessage(this.store, {
        parent: this.meeting,
        author: this.manifest.personas.mara,
        text,
      });
    } catch (e) {
      console.warn('[Demo] could not narrate:', e);
    } finally {
      this.selfSaving = false;
    }
  }

  // ─── Meeting ─────────────────────────────────────────────────────

  /** Mara starts the tour Meeting: lists it in the drive's `currentMeetings`,
   *  which makes it live (and, for a visitor who has it open, joins them to
   *  it and opens its chat). The Meeting itself was made with the workspace.
   *  The drive update is user-signed (only the user's agent can), guarded
   *  against the reactive triggers. */
  private async startTourMeeting(): Promise<void> {
    if (this.meeting || this.stopped) return;
    this.selfSaving = true;

    try {
      const meeting = this.manifest.meeting;
      const drive = await this.store.getResource(this.manifest.drive);
      drive.push(dataBrowser.properties.currentMeetings, [meeting], true);
      await drive.save();

      this.meeting = meeting;
    } catch (e) {
      console.warn('[Demo] could not start meeting:', e);
    } finally {
      this.selfSaving = false;
    }
  }

  /** De-list the tour meeting (the log resource stays). */
  private async endTourMeeting(): Promise<void> {
    const meeting = this.meeting;
    if (!meeting) return;

    // Close the feed with an explicit end marker before de-listing.
    await createDemoMessage(this.store, {
      parent: meeting,
      author: this.manifest.personas.mara,
      text: 'The meeting has ended.',
      extraClasses: [dataBrowser.classes.followEvent],
    }).catch(() => undefined);

    const meetingResource = await this.store.getResource(meeting);
    await meetingResource.set(
      dataBrowser.properties.meetingEndedAt,
      Date.now(),
    );
    await meetingResource.save();

    this.meeting = undefined;
    this.selfSaving = true;

    try {
      const drive = await this.store.getResource(this.manifest.drive);
      const current = (drive.get(dataBrowser.properties.currentMeetings) ??
        []) as string[];
      await drive.set(
        dataBrowser.properties.currentMeetings,
        current.filter(subject => subject !== meeting),
      );
      await drive.save();
    } catch (e) {
      console.warn('[Demo] could not end meeting:', e);
    } finally {
      this.selfSaving = false;
    }
  }

  // ─── Timing ──────────────────────────────────────────────────────

  private sleep(
    ms: number,
    { pauseWhenHidden = true }: { pauseWhenHidden?: boolean } = {},
  ): Promise<void> {
    return new Promise(resolve => {
      const finish = () => {
        // Pause while the tab is hidden: resume (and only then resolve)
        // once the user is back, so they don't miss the show.
        if (pauseWhenHidden && document.hidden && !this.stopped) {
          const onVisible = () => {
            document.removeEventListener('visibilitychange', onVisible);
            resolve();
          };

          document.addEventListener('visibilitychange', onVisible);
        } else {
          resolve();
        }
      };

      setTimeout(finish, ms);
    });
  }

  /** Resolves `true` once the user's presence entry starts following
   *  Mara (i.e. they clicked Join), `false` after the timeout. */
  private waitForJoin(timeoutMs: number): Promise<boolean> {
    if (this.maraFollowed) return Promise.resolve(true);

    return new Promise<boolean>(resolve => {
      const start = Date.now();
      const timer = setInterval(() => {
        if (this.stopped || this.maraFollowed) {
          clearInterval(timer);
          resolve(this.maraFollowed);
        } else if (Date.now() - start > timeoutMs) {
          clearInterval(timer);
          resolve(false);
        }
      }, 400);
    });
  }

  /** Resolves `true` once the user posts a message in the meeting chat,
   *  `false` after the timeout. */
  private waitForUserChat(timeoutMs: number): Promise<boolean> {
    if (this.userChatted) return Promise.resolve(true);

    return new Promise<boolean>(resolve => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      this.userChatWaiters.push(() => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  }
}

/** Follow-trail entry matching FollowContext's format: a markdown link
 *  to what the followed agent is looking at. */
function viewingMessage(store: Store, subject: string): string {
  const title =
    (store.resources.get(subject)?.get(core.properties.name) as
      | string
      | undefined) ?? 'a resource';

  return `Viewing [${title}](${subject})`;
}
