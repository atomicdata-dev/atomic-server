import { test, expect, type Page } from './fixtures';
import { before, getDevDriveSecret, signIn, FRONTEND_URL } from './test-utils';

/**
 * Drive presence + follow mode (#1229), driven as two sessions (browser
 * contexts) of the same agent in one drive:
 *
 * 1. Presence: each session sees the other's avatar in the navbar facepile.
 * 2. Follow: B follows via the avatar menu → compact "Following" badge,
 *    and the followed avatar leaves the facepile (deduped into the badge).
 * 3. The leader (A) sees the "Following you" badge.
 * 4. Live following: A navigates to a folder → B auto-navigates along.
 *
 * This pins the client stack (presence manager, websocket resubscribe
 * ordering, LWW entry patching, follow context) that the Rust integration
 * tests can't see. The shared session chat / trail now lives in Meetings
 * (#1127) — see meetings.spec.ts; plain follow is navigation-only.
 */

const followingBadge = (page: Page) =>
  page.getByTitle('Following — press for actions');
const followingYouBadge = (page: Page) =>
  page.getByTitle('These users follow you — press for actions');
const facepile = (page: Page) =>
  page.locator('[aria-label="Also viewing this resource"]');

test('presence avatars and follow mode across two sessions', async ({
  browser,
}) => {
  test.setTimeout(120_000);

  // --- Session A (the leader): dev drive + a folder to navigate to ---
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  await before({ page: pageA });

  // devDrive() can fire a late redirect after its readiness checks;
  // an evaluate caught mid-navigation dies with "context destroyed".
  await pageA.waitForLoadState('load');
  let created!: { drive: string; folder: string };
  await expect(async () => {
    created = await pageA.evaluate(async () => {
      const s = window.store;
      const d = s.getDrive();

      if (!d) throw new Error('no drive');

      const tmp = await s.createSubject('presence-e2e');
      const f = await s.newResource({
        subject: tmp,
        parent: d,
        isA: 'https://atomicdata.dev/classes/Folder',
      });
      await f.set(
        'https://atomicdata.dev/properties/name',
        'FollowTarget',
        false,
      );
      await f.save();

      return { drive: d, folder: f.subject };
    });
  }).toPass({ timeout: 30_000 });
  const { drive, folder } = created;
  const secret = await getDevDriveSecret(pageA);

  await pageA.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
  );

  // --- Session B (the follower): same agent, fresh context ---
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  await pageB.goto(FRONTEND_URL);
  await signIn(pageB, secret);
  await pageB.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
  );

  // 1. Presence: both sessions see each other in the navbar facepile.
  await expect(facepile(pageB).getByRole('button').first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(facepile(pageA).getByRole('button').first()).toBeVisible({
    timeout: 30_000,
  });

  // 2. B follows A via the avatar's context menu. The trigger remounts
  // when the agent's name resolves (closing the menu), so open-and-click
  // as one retried unit.
  await expect(async () => {
    // Close any half-open menu from a previous attempt, then open fresh.
    await pageB.keyboard.press('Escape');
    await facepile(pageB).getByRole('button').first().click();
    await pageB
      .getByRole('menuitem', { name: 'Follow', exact: true })
      .click({ timeout: 2000 });
  }).toPass({ timeout: 30_000 });
  await expect(followingBadge(pageB)).toBeVisible();
  // The followed agent's avatar moves into the badge — facepile empties.
  await expect(facepile(pageB)).toHaveCount(0);

  // 3. The leader sees who's following them.
  await expect(followingYouBadge(pageA)).toBeVisible({ timeout: 30_000 });

  // 4. Leader navigates (in-app, via the sidebar); the follower is taken
  // along. A full-page goto would start a NEW presence session and leave
  // the old one lingering until its TTL — in-app navigation is also what
  // a real leader does.
  await pageA.getByRole('button', { name: 'FollowTarget' }).first().click();
  await expect(pageA).toHaveURL(
    new RegExp(
      encodeURIComponent(folder).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    ),
  );
  await expect(pageB).toHaveURL(
    new RegExp(
      encodeURIComponent(folder).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    ),
    { timeout: 30_000 },
  );

  await ctxA.close();
  await ctxB.close();
});
