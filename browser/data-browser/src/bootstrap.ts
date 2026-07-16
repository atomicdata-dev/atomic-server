import { core, JSONADParser, type Resource, type Store } from '@tomic/react';
import baseModels from '@repo-lib-defaults/default_base_models.json';
import defaultStore from '@repo-lib-defaults/default_store.json';
import tableDefaults from '@repo-lib-defaults/table.json';
import dashboardDefaults from '@repo-lib-defaults/dashboard.json';
import chatroomDefaults from '@repo-lib-defaults/chatroom.json';
import ontologiesDefaults from '@repo-lib-defaults/ontologies.json';
import aiDefaults from '@repo-lib-defaults/ai.json';
import meetingDefaults from '@repo-lib-defaults/meeting.json';
import forksDefaults from '@repo-lib-defaults/forks.json';
import formsDefaults from '@repo-lib-defaults/forms.json';
import pluginsDefaults from '@repo-lib-defaults/plugins.json';

/**
 * A bundled entry that holds no content of its own — no class, and no
 * properties beyond the `parent` that places it in the tree. The real resource
 * lives on the server; this is only here so the definitions shipped alongside
 * it have somewhere to hang.
 */
function isAnchorStub(resource: Resource): boolean {
  if (resource.get(core.properties.isA)) {
    return false;
  }

  return Object.keys(resource.getPropVals()).every(
    prop => prop === core.properties.parent,
  );
}

/**
 * Injects base models and default store resources into the store.
 * This ensures that critical property definitions (like 'subdomain') are
 * available even if the server has no Drive binding yet or the definitions haven't
 * been uploaded to the live atomicdata.dev server yet.
 *
 * Every default set the server imports in `lib/src/populate.rs`
 * (`populate_default_store`) must also be added here. A missing set makes
 * `resource.set()` datatype validation fetch the property from the real
 * atomicdata.dev — which doesn't host it — stalling every write to it for up
 * to 10s (the `getResource` not-ready timeout).
 */
export function bootstrap(store: Store): void {
  const parser = new JSONADParser();

  const addBootstrapped = (json: unknown) => {
    const resources = parser.parse(json);

    for (const r of resources) {
      r.loading = false;

      // Some bundled entries are pure anchors: they exist only to hold the
      // parent chain of the definitions shipped alongside them, and carry
      // nothing but `parent` (`atomicdata.dev/properties`, `/classes`,
      // `/datatypes`, `/ontology/canvas`). Mark those `incomplete` so visiting
      // the subject still triggers a real fetch — `getResourceLoading`
      // refetches incomplete resources. Without the marker the stub reads as
      // fully loaded and shadows the real resource forever: no fetch, no
      // error, an empty page.
      //
      // A stub carrying content of its own is NOT an anchor, even without a
      // class. `agents/publicAgent` (description + shortname) is the one that
      // proves the difference: marking it sends every rights UI off to
      // atomicdata.dev before it will enable a checkbox, so the "Public"
      // toggle on the share page stays disabled for as long as that fetch is
      // pending — forever, on a server with no route to the internet.
      if (isAnchorStub(r)) {
        r.applyHydratedValues([[core.properties.incomplete, true]]);
      }

      store.applyIncoming({
        subject: r.subject,
        resource: r,
        source: 'offline-replay',
      });
    }

    return resources.length;
  };

  try {
    addBootstrapped(baseModels);
    addBootstrapped(defaultStore);
    addBootstrapped(tableDefaults);
    addBootstrapped(dashboardDefaults);
    addBootstrapped(chatroomDefaults);
    addBootstrapped(ontologiesDefaults);
    addBootstrapped(aiDefaults);
    addBootstrapped(meetingDefaults);
    addBootstrapped(forksDefaults);
    addBootstrapped(formsDefaults);
    addBootstrapped(pluginsDefaults);
  } catch (e) {
    console.error('Failed to bootstrap store:', e);
  }
}
