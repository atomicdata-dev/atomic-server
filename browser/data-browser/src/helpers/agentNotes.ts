// @wc-ignore-file
import {
  core,
  Datatype,
  dataBrowser,
  type QueryFilter,
  type Store,
} from '@tomic/react';

/**
 * Your notes on an agent live in your own private drive, as a PlainText
 * (name + description) whose `about` points at that agent. Nothing on the
 * agent's side refers to it, so they can't read it, and the private drive is
 * the one place that syncs to all your devices.
 */
export function agentNoteQuery(
  privateDrive: string,
  agent: string,
): QueryFilter {
  return {
    property: dataBrowser.properties.about,
    value: agent,
    filters: [
      { property: core.properties.isA, value: dataBrowser.classes.plainText },
    ],
    drive: privateDrive,
  };
}

/** Creates the (empty) note on `agent` and returns its subject. */
export async function createAgentNote(
  store: Store,
  privateDrive: string,
  agent: string,
  agentName: string,
): Promise<string> {
  const note = await store.newResource({
    parent: privateDrive,
    isA: dataBrowser.classes.plainText,
    propVals: {
      [core.properties.name]: `Notes on ${agentName}`,
      // PlainText requires one; the note's text goes here.
      [core.properties.description]: '',
      [dataBrowser.properties.about]: agent,
    },
    propDatatypes: {
      [dataBrowser.properties.about]: Datatype.ATOMIC_URL,
    },
  });
  await note.save();
  store.notifyResourceManuallyCreated(note);

  return note.subject;
}
