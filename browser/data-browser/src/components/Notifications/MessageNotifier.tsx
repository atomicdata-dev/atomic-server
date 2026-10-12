import { useEffect, useEffectEvent, useRef } from 'react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import {
  core,
  dataBrowser,
  StoreEvents,
  useCurrentAgent,
  useStore,
  type Resource,
  type Store,
} from '@tomic/react';
import { AgentAvatar } from '../Presence/AgentAvatar';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';
import { parseEntryId } from '../../helpers/chatLog';
import {
  classifyMessage,
  entryFacts,
  isCandidate,
  type MessageFacts,
  type MessageNotification,
} from '../../helpers/notifications/messageNotification';
import {
  declineOsNotifications,
  shouldOfferOsNotifications,
  showOsNotification,
  turnOnOsNotifications,
} from '../../helpers/notifications/osNotifications';
import { Button } from '../Button';
import {
  markReadAbout,
  recordNotification,
} from '../../helpers/notifications/inbox';
import { usePrivateDrive } from '../../hooks/usePrivateDrive';
import { usePrivateDriveList } from '../../hooks/usePrivateDriveList';

const TEXT_MAX = 140;

/** Messages created before the app started are backlog, not news. */
const APP_STARTED = Date.now();

function factsOf(resource: Resource): MessageFacts {
  const stable = resource.stable;

  const str = (prop: string) => {
    const v = stable.get(prop);

    return typeof v === 'string' ? v : undefined;
  };

  return {
    subject: stable.subject,
    isA: (stable.get(core.properties.isA) as string[] | undefined) ?? [],
    createdAt: stable.getCreatedAt(),
    createdBy: stable.getCreatedBy(),
    parent: str(core.properties.parent),
    about: str(dataBrowser.properties.about),
    replyTo: str(dataBrowser.properties.replyTo),
  };
}

async function loadAll(store: Store, subjects: (string | undefined)[]) {
  const loaded = new Map<string, Resource>();
  await Promise.all(
    subjects.map(async s => {
      if (!s) return;
      const r = await store.getResource(s);
      if (!r.error) loaded.set(s, r);
    }),
  );

  return loaded;
}

function headline(
  kind: MessageNotification['kind'],
  author: string,
  on: string,
) {
  switch (kind) {
    case 'reply':
      return `${author} replied to you`;
    case 'comment':
      return `${author} commented on ${on}`;
    case 'chat':
      return `${author} in ${on}`;
  }
}

/**
 * Tells you about new chat messages, comments on things you made and replies
 * to you, while the app is open. A toast when you're looking at the app, an
 * OS notification when you aren't (another tab, window or app), and nothing
 * when you're already looking at the conversation. Only messages created
 * after the app started count: the backlog is not news. Renders nothing.
 */
export function MessageNotifier(): null {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const [currentSubject] = useCurrentSubject();
  const { activePanel, setPanelOpen } = useRightPanel();
  const navigate = useNavigateWithTransition();
  const { privateDrive } = usePrivateDrive();
  const [sharedWithMe] = usePrivateDriveList(core.properties.sharedWithMe);

  const handled = useRef(new Set<string>());
  // Announced while away, with system notifications not decided yet.
  const missed = useRef(0);
  // Inbox writes still in flight, per target, so reading waits for them.
  const recording = useRef(new Map<string, Promise<unknown>>());

  const readAbout = useEffectEvent((target: string, upTo = Date.now()) => {
    if (!privateDrive) return;

    const pending = recording.current.get(target) ?? Promise.resolve();

    void pending
      .then(() => markReadAbout(store, privateDrive, target, upTo))
      .catch(e => console.error('Could not mark notifications read:', e));
  });

  const open = useEffectEvent((n: MessageNotification) => {
    navigate(constructOpenURL(n.target));
    if (n.openComments) setPanelOpen('comments', true);
    readAbout(n.target);
  });

  // Opening something reads what the Inbox says about it, and so does coming
  // back to the window while it is still open: what arrived while you were
  // away was announced by the OS, and is on screen now.
  useEffect(() => {
    if (!currentSubject) return;

    readAbout(currentSubject);

    const onReturn = () => {
      if (!document.hidden && document.hasFocus()) readAbout(currentSubject);
    };

    window.addEventListener('focus', onReturn);
    document.addEventListener('visibilitychange', onReturn);

    return () => {
      window.removeEventListener('focus', onReturn);
      document.removeEventListener('visibilitychange', onReturn);
    };
  }, [currentSubject]);

  // Back after missing something: offer system notifications, once. A
  // checkbox in Settings alone meant nobody turned them on, so everything
  // that arrived while the app was in the background went unannounced.
  useEffect(() => {
    const onReturn = () => {
      if (document.hidden || !document.hasFocus() || missed.current === 0) {
        return;
      }

      const count = missed.current;
      missed.current = 0;

      if (!shouldOfferOsNotifications()) return;

      toast.custom(
        t => (
          <OfferCard role='status'>
            <ToastTitle as='p'>
              {count === 1
                ? 'You missed a message while you were away'
                : `You missed ${count} messages while you were away`}
            </ToastTitle>
            <ToastText as='p'>
              Show new messages as system notifications on this device?
            </ToastText>
            <OfferButtons>
              <Button
                onClick={() => {
                  toast.dismiss(t.id);
                  void turnOnOsNotifications();
                }}
              >
                Turn on
              </Button>
              <Button
                subtle
                onClick={() => {
                  toast.dismiss(t.id);
                  declineOsNotifications();
                }}
              >
                Not now
              </Button>
            </OfferButtons>
          </OfferCard>
        ),
        { duration: Infinity, id: 'offer-os-notifications' },
      );
    };

    window.addEventListener('focus', onReturn);
    document.addEventListener('visibilitychange', onReturn);

    return () => {
      window.removeEventListener('focus', onReturn);
      document.removeEventListener('visibilitychange', onReturn);
    };
  }, []);

  const isLookingAt = useEffectEvent((n: MessageNotification) => {
    if (document.hidden || !document.hasFocus()) return false;
    if (!currentSubject) return false;

    if (
      store.normalizeSubject(currentSubject) !==
      store.normalizeSubject(n.target)
    ) {
      return false;
    }

    return !n.openComments || activePanel === 'comments';
  });

  const announce = useEffectEvent(
    async (facts: MessageFacts, text: string): Promise<void> => {
      const subject = facts.subject;
      const ctx = { me: agent?.subject, since: APP_STARTED };

      // Replies can point at an entry; its author is on the entry's page.
      const replyPage = facts.replyTo && parseEntryId(facts.replyTo)?.page;
      const related = await loadAll(store, [
        facts.parent,
        facts.about,
        replyPage || facts.replyTo,
        facts.createdBy,
      ]);
      const n = classifyMessage(facts, {
        ...ctx,
        classesOf: s =>
          related.get(s)?.get(core.properties.isA) as string[] | undefined,
        creatorOf: s => {
          const entry = parseEntryId(s);

          return entry
            ? related.get(entry.page)?.getChatLogEntry(entry.key)?.a
            : related.get(s)?.getCreatedBy();
        },
      });

      if (!n) return;

      if (isLookingAt(n)) {
        // Another open device may still record it; read that copy too.
        const seenAt = Date.now();
        setTimeout(() => readAbout(n.target, seenAt), 3000);

        return;
      }

      const authorName = related.get(n.author)?.title ?? 'Someone';
      const targetTitle = related.get(n.target)?.title ?? '';
      const title = headline(n.kind, authorName, targetTitle);
      const body =
        text.length > TEXT_MAX ? `${text.slice(0, TEXT_MAX)}…` : text;

      if (privateDrive) {
        const before = recording.current.get(n.target);
        const record = recordNotification(store, privateDrive, {
          source: subject,
          about: n.target,
          kind: n.kind,
          actor: n.author,
          title,
          body,
          occurredAt: facts.createdAt ?? Date.now(),
        }).catch(e => console.error('Could not add to the inbox:', e));
        const all = Promise.all([before, record]);
        recording.current.set(n.target, all);
        void all.then(() => {
          if (recording.current.get(n.target) === all) {
            recording.current.delete(n.target);
          }
        });
      }

      if (!document.hidden && document.hasFocus()) {
        toast.custom(
          t => (
            <ToastCard
              type='button'
              onClick={() => {
                open(n);
                toast.dismiss(t.id);
              }}
            >
              <AgentAvatar agentSubject={n.author} size='1.8rem' />
              <ToastBody>
                <ToastTitle>{title}</ToastTitle>
                <ToastText>{body}</ToastText>
              </ToastBody>
            </ToastCard>
          ),
          { duration: 6000, id: subject },
        );

        return;
      }

      if (shouldOfferOsNotifications()) missed.current += 1;

      showOsNotification({ title, body, tag: subject, onClick: () => open(n) });
    },
  );

  const onUpdate = useEffectEvent(async (resource: Resource) => {
    const subject = resource.stable.subject;
    const ctx = { me: agent?.subject, since: APP_STARTED };
    const classes =
      (resource.stable.get(core.properties.isA) as string[] | undefined) ?? [];

    // A page of a chat log: its entries are the messages. Every update asks
    // about all of them; the ones already handled (and edits of those) are
    // skipped.
    if (classes.includes(dataBrowser.classes.chatLog)) {
      const page = resource.stable;

      for (const { key, entry } of page.listChatLogEntries()) {
        const facts = entryFacts(page.subject, factsOf(page), key, entry);

        if (handled.current.has(facts.subject)) continue;

        // Not decidable yet: the page's own metadata hasn't arrived.
        if (isCandidate(facts, ctx) === undefined) continue;

        handled.current.add(facts.subject);

        if (isCandidate(facts, ctx)) await announce(facts, entry.t);
      }

      return;
    }

    if (handled.current.has(subject)) return;

    const facts = factsOf(resource);
    const candidate = isCandidate(facts, ctx);

    // Not decidable yet: its genesis hasn't arrived. A later update will ask again.
    if (candidate === undefined) return;

    handled.current.add(subject);

    if (!candidate) return;

    await announce(
      facts,
      (resource.stable.get(core.properties.description) as
        | string
        | undefined) ?? '',
    );
  });

  // Things shared with you out of drives you can't open are only delivered to
  // a subscription on the thing itself; the open drive's subscription never
  // covers them. Hold one for as long as the app runs, not only while the
  // sidebar happens to show the item, or a shared chat stays silent.
  useEffect(() => {
    const unsubscribers = sharedWithMe.map(subject =>
      store.subscribeLive(subject),
    );

    return () => unsubscribers.forEach(unsubscribe => unsubscribe());
  }, [store, sharedWithMe]);

  useEffect(
    () =>
      store.on(StoreEvents.ResourceUpdated, resource => {
        void onUpdate(resource).catch(e =>
          console.error('Could not show a notification:', e),
        );
      }),
    [store],
  );

  return null;
}

const ToastCard = styled.button`
  display: flex;
  align-items: center;
  gap: 0.6rem;
  max-width: 22rem;
  padding: 0.6rem 0.8rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  cursor: pointer;
  text-align: left;
  color: ${p => p.theme.colors.text};
`;

const OfferCard = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  max-width: 22rem;
  padding: 0.8rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  color: ${p => p.theme.colors.text};

  & p {
    margin: 0;
    white-space: normal;
  }
`;

const OfferButtons = styled.div`
  display: flex;
  gap: 0.5rem;
  margin-top: 0.2rem;
`;

const ToastBody = styled.span`
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

const ToastTitle = styled.span`
  font-weight: 600;
  font-size: 0.8rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ToastText = styled.span`
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;
