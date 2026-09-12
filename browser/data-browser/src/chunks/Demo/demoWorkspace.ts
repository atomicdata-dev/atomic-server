// @wc-ignore-file
// (Wuchale: demo starter content — localization tracked in
// planning/demo-experience.md.)
// React Compiler: plain creation helpers, not components (see DemoDirector.ts).
'use no memo';
import {
  core,
  dataBrowser,
  canvas,
  commits,
  server,
  classes,
  type JSONValue,
  type Resource,
  type Store,
} from '@tomic/react';
import { buildTableFromSpec } from '../TablePage/createTableFromSpec';
import { DEMO_SPEAKER } from './messageSpeaker';
import { MOODBOARD_BAKED_STROKES } from './moodboardStrokes';

/**
 * The demo workspace: a LOCAL-ONLY drive ("Atomic Demo") populated with
 * starter content, plus three scripted teammates. Everything is created
 * through the normal client-side creation paths (`newResource` genesis
 * → `save()`), which the local-only drive mode routes to OPFS instead
 * of a server. See `planning/demo-experience.md`.
 */

const MANIFEST_KEY = 'atomic.demoWorkspace';

export type PersonaKey = 'mara' | 'yusuf' | 'pip';
export type ChecklistStatus = 'Todo' | 'Doing' | 'Done';

export interface DemoManifest {
  drive: string;
  welcomeDoc: string;
  assetsFolder: string;
  moodboard: string;
  team: {
    table: string;
    rowClass: string;
    roleColumn: string;
    responsibilitiesColumn: string;
    doingTaskColumn: string;
    onboardingColumn: string;
  };
  checklist: {
    table: string;
    rowClass: string;
    statusColumn: string;
    ownerColumn: string;
    statusTags: Record<ChecklistStatus, string>;
    /** Row subjects in creation order (see `CHECKLIST_ROWS`). */
    rows: string[];
  };
  /** The visible "Team chat" room, pre-seeded with persona banter. */
  teamChat: string;
  /** Persona key → subject of their Team-table row (used as their
   *  presence agent + message author). */
  personas: Record<PersonaKey, string>;
}

export function loadDemoManifest(): DemoManifest | undefined {
  try {
    const raw = localStorage.getItem(MANIFEST_KEY);

    return raw ? (JSON.parse(raw) as DemoManifest) : undefined;
  } catch {
    return undefined;
  }
}

export function saveDemoManifest(manifest: DemoManifest | undefined): void {
  if (manifest === undefined) {
    localStorage.removeItem(MANIFEST_KEY);
  } else {
    localStorage.setItem(MANIFEST_KEY, JSON.stringify(manifest));
  }
}

export const PERSONAS: Record<
  PersonaKey,
  {
    name: string;
    role: string;
    /** Tag options for the "Responsibilities" select column. */
    responsibilities: string[];
    /** Index into `CHECKLIST_ROWS` this member is currently "Doing" —
     *  wired up as the relation column's target. */
    doingTaskRow: number;
  }
> = {
  mara: {
    name: 'Mara',
    role: 'Product — keeps the launch on the rails',
    responsibilities: ['Product', 'Docs'],
    // "Join the onboarding meeting" — the card she's running the user through.
    doingTaskRow: 0,
  },
  yusuf: {
    name: 'Yusuf',
    role: 'Design — communicates primarily in emoji',
    responsibilities: ['Design'],
    // "Doodle on the moodboard" — his card.
    doingTaskRow: 3,
  },
  pip: {
    name: 'Pip',
    role: 'Engineering — ships the actual thing',
    responsibilities: ['Engineering', 'QA'],
    // "Explore the kanban board" — he set the board up.
    doingTaskRow: 1,
  },
};

/** Tag options offered by the Team table's "Responsibilities" column. */
const RESPONSIBILITY_OPTIONS = [
  'Product',
  'Design',
  'Engineering',
  'QA',
  'Docs',
];

/**
 * The board is META: every card is a step in the user's own onboarding
 * tour, so the demo can literally drag "Explore the kanban board" to
 * Done while showing off the kanban board.
 */
/** "Explore the kanban board" — Mara drags this Todo→Doing→Done live. */
export const ROW_EXPLORE_BOARD = 1;
/** "Say hi in the meeting chat" — moved to Done when the user chats. */
export const ROW_SAY_HI = 2;
/** "Doodle on the moodboard" — Yusuf owns it. */
export const ROW_DOODLE = 3;

const CHECKLIST_ROWS: Array<Record<string, JSONValue>> = [
  { name: 'Join the onboarding meeting', Status: 'Done', Owner: 'Mara' },
  { name: 'Explore the kanban board', Status: 'Todo', Owner: 'You' },
  { name: 'Say hi in the meeting chat', Status: 'Todo', Owner: 'You' },
  { name: 'Doodle on the moodboard', Status: 'Doing', Owner: 'Yusuf' },
  { name: 'Make the workspace your own', Status: 'Todo', Owner: 'You' },
];

const TEAM_CHAT_SEED: Array<{ author: PersonaKey; text: string }> = [
  {
    author: 'mara',
    text: 'Morning! New teammate joins today — I’ll run them through an onboarding meeting.',
  },
  { author: 'pip', text: 'nice, the onboarding board is all set up 👍' },
  {
    author: 'yusuf',
    text: 'moodboard’s ready for them to scribble on 🎨',
  },
];

/** Create local scripted speech while preserving the real genesis creator. */
export async function createDemoMessage(
  store: Store,
  opts: {
    parent: string;
    author: string;
    text: string;
    extraClasses?: string[];
  },
): Promise<Resource> {
  const message = await store.newResource({
    parent: opts.parent,
    isA: [dataBrowser.classes.message, ...(opts.extraClasses ?? [])],
    propVals: {
      [core.properties.description]: opts.text,
      [DEMO_SPEAKER]: opts.author,
    },
  });
  await message.save();

  return message;
}

/** Mirrors `useAddToOntology` for imperative (non-hook) callers: parent
 *  the class/property under the drive's default ontology and link it in
 *  the matching ontology list. */
export async function addToOntology(
  store: Store,
  driveSubject: string,
  resource: Resource,
): Promise<void> {
  const drive = await store.getResource(driveSubject);
  const ontologySubject = drive.get(server.properties.defaultOntology) as
    | string
    | undefined;

  if (!ontologySubject) {
    await resource.set(core.properties.parent, driveSubject);
    await resource.save();

    return;
  }

  await resource.set(core.properties.parent, ontologySubject);
  await resource.save();

  const ontology = await store.getResource(ontologySubject);

  if (resource.hasClasses(core.classes.class)) {
    ontology.push(core.properties.classes, [resource.subject], true);
  } else if (resource.hasClasses(core.classes.property)) {
    ontology.push(core.properties.properties, [resource.subject], true);
  } else {
    ontology.push(core.properties.instances, [resource.subject], true);
  }

  await ontology.save();
}

/** A guest agent's resource exists nowhere else, so give it a local
 *  profile: a row in the Team table (they really are on the team) whose
 *  subject is the agent DID, so avatars and names resolve offline. */
async function createGuestProfile(
  store: Store,
  agentSubject: string,
  team: DemoManifest['team'],
): Promise<void> {
  const profile = store.getResourceLoading(agentSubject, {
    newResource: true,
  });

  await profile.set(
    core.properties.publicKey,
    agentSubject.replace('did:ad:agent:', ''),
  );
  await profile.set(core.properties.isA, [core.classes.agent, team.rowClass]);
  await profile.set(core.properties.name, 'Demo User');
  await profile.set(team.roleColumn, 'New teammate', false);
  // Their first day — onboarding not yet complete (the tour ticks it).
  await profile.set(team.onboardingColumn, false, false);
  // Created after the seeded members, so the createdAt-ascending default
  // sort lands this row at the BOTTOM of the table, not the top.
  await profile.set(commits.properties.createdAt, Date.now(), false);
  await profile.set(core.properties.parent, team.table);
  // A component may have tried to fetch this agent from the server
  // (404) before the profile existed — clear the error BEFORE the save
  // notifies subscribers, so they re-render with the local profile
  // instead of "error loading resource".
  profile.error = undefined;
  await profile.save();
}

/** Best-effort: list the demo drive in the user's drive switcher. The
 *  personal drive is a real synced drive, so this edit goes to the
 *  server like any other — only the demo drive itself stays local. */
async function addToSavedDrives(store: Store, drive: string): Promise<void> {
  try {
    const agentSubject = store.getAgent()?.subject;
    if (!agentSubject) return;

    const agentResource = await store.getResource(agentSubject);
    const privateDrive = agentResource.get(core.properties.personalDrive) as
      | string
      | undefined;
    if (!privateDrive) return;

    const privateDriveResource = await store.getResource(privateDrive);
    privateDriveResource.push(server.properties.drives, [drive], true);
    await privateDriveResource.save();
  } catch {
    // No personal drive (yet) — the demo still works via direct navigation.
  }
}

export interface CreateDemoWorkspaceOpts {
  /** The agent is a freshly-minted anonymous guest: give it a local
   *  profile in the Team table and skip the drive-switcher link (a
   *  guest has no personal drive). */
  guest?: boolean;
}

export async function createDemoWorkspace(
  store: Store,
  opts: CreateDemoWorkspaceOpts = {},
): Promise<DemoManifest> {
  const agent = store.getAgent();

  if (!agent?.subject) {
    throw new Error('Cannot create the demo workspace without an agent.');
  }

  // The drive: registered local-only BETWEEN genesis (which derives the
  // subject) and the first save (which must already route locally).
  const drive = await store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: {
      [core.properties.name]: 'Atomic Demo',
      [core.properties.description]:
        'The demo team’s workspace. Lives entirely on this device — edit anything.',
      [core.properties.write]: [agent.subject],
      [core.properties.read]: [agent.subject],
    },
  });
  store.registerLocalOnlyDrive(drive.subject);
  await drive.save();

  await store.createDefaultOntology(drive);

  const welcomeDoc = await store.newResource({
    parent: drive.subject,
    isA: dataBrowser.classes.documentV2,
    propVals: { [core.properties.name]: 'Welcome 👋' },
  });
  await welcomeDoc.save();

  // The Issue Tracker is a kanban board: cards grouped by Status.
  const checklistResult = await buildTableFromSpec(
    store,
    {
      name: 'Issue Tracker',
      rowName: 'Task',
      columns: [
        { name: 'Status', type: 'select', options: ['Todo', 'Doing', 'Done'] },
        { name: 'Owner', type: 'text' },
      ],
      views: [
        {
          name: 'Board',
          kind: 'kanban',
          groupByColumn: 'Status',
          default: true,
        },
      ],
      rows: CHECKLIST_ROWS,
    },
    {
      parent: drive.subject,
      driveSubject: drive.subject,
      addToOntology: resource => addToOntology(store, drive.subject, resource),
    },
  );

  // The team is a table: one row per member, and the rows double as the
  // personas' identities (presence agent + message author subjects). It
  // deliberately exercises several column types — text (Role), tags
  // (Responsibilities), a relation (Doing task → a checklist card), and a
  // checkbox (Completed onboarding) — so the demo showcases the table.
  const teamResult = await buildTableFromSpec(
    store,
    {
      name: 'Team',
      rowName: 'Member',
      columns: [
        { name: 'Role', type: 'text' },
        {
          name: 'Responsibilities',
          type: 'select',
          options: RESPONSIBILITY_OPTIONS,
        },
        { name: 'Doing task', type: 'relation' },
        { name: 'Completed onboarding', type: 'checkbox' },
      ],
      rows: (Object.keys(PERSONAS) as PersonaKey[]).map(key => ({
        name: PERSONAS[key].name,
        Role: PERSONAS[key].role,
        Responsibilities: PERSONAS[key].responsibilities,
        'Doing task': checklistResult.rowSubjects[PERSONAS[key].doingTaskRow],
        // The scripted teammates are veterans — already onboarded.
        'Completed onboarding': true,
      })),
    },
    {
      parent: drive.subject,
      driveSubject: drive.subject,
      addToOntology: resource => addToOntology(store, drive.subject, resource),
    },
  );

  const team: DemoManifest['team'] = {
    table: teamResult.tableSubject,
    rowClass: teamResult.classSubject,
    roleColumn: teamResult.columns['Role'],
    responsibilitiesColumn: teamResult.columns['Responsibilities'],
    doingTaskColumn: teamResult.columns['Doing task'],
    onboardingColumn: teamResult.columns['Completed onboarding'],
  };

  const personas = {} as Record<PersonaKey, string>;
  (Object.keys(PERSONAS) as PersonaKey[]).forEach((key, index) => {
    personas[key] = teamResult.rowSubjects[index];
  });

  const moodboard = await store.newResource({
    parent: drive.subject,
    isA: canvas.classes.canvas,
    propVals: {
      [core.properties.name]: 'Moodboard',
      // Hand-drawn creatures (native JSON array — strokeData's datatype
      // is json). Yusuf draws the rest live during the tour.
      [canvas.properties.strokeData]: MOODBOARD_BAKED_STROKES as JSONValue,
    },
  });
  await moodboard.save();

  const assetsFolder = await store.newResource({
    parent: drive.subject,
    isA: dataBrowser.classes.folder,
    propVals: {
      [core.properties.name]: 'Assets',
      [dataBrowser.properties.displayStyle]: classes.displayStyles.list,
    },
  });
  await assetsFolder.save();

  // Team chat, pre-seeded so the room feels lived-in.
  const teamChat = await store.newResource({
    parent: drive.subject,
    isA: dataBrowser.classes.chatroom,
    propVals: { [core.properties.name]: 'Team chat' },
  });
  await teamChat.save();

  for (const seed of TEAM_CHAT_SEED) {
    await createDemoMessage(store, {
      parent: teamChat.subject,
      author: personas[seed.author],
      text: seed.text,
    });
  }

  if (opts.guest) {
    await createGuestProfile(store, agent.subject, team);
  } else {
    await addToSavedDrives(store, drive.subject);
  }

  const manifest: DemoManifest = {
    drive: drive.subject,
    welcomeDoc: welcomeDoc.subject,
    assetsFolder: assetsFolder.subject,
    moodboard: moodboard.subject,
    team,
    checklist: {
      table: checklistResult.tableSubject,
      rowClass: checklistResult.classSubject,
      statusColumn: checklistResult.columns['Status'],
      ownerColumn: checklistResult.columns['Owner'],
      statusTags: checklistResult.tags['Status'] as Record<
        ChecklistStatus,
        string
      >,
      rows: checklistResult.rowSubjects,
    },
    teamChat: teamChat.subject,
    personas,
  };

  saveDemoManifest(manifest);

  return manifest;
}
