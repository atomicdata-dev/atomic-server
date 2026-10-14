import { useEffect, useEffectEvent, useRef } from 'react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import {
  core,
  CollectionBuilder,
  dataBrowser,
  StoreEvents,
  RequestCancelledError,
  useCurrentAgent,
  useStore,
  type Resource,
  type Store,
} from '@tomic/react';
import { AgentAvatar } from '../Presence/AgentAvatar';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { useFollow } from '../Presence/FollowContext';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';
import { parseEntryId } from '../../helpers/chatLog';
import {
  bubbleId,
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
import { demoForDrive } from '../../chunks/Templates/demoSession';
import { notificationSourceId } from '../../helpers/notifications/identity';

const TEXT_MAX = 140;

/** Only messages created during this app session produce transient alerts. */
const APP_STARTED = Date.now();

/**
 * Entries announced (or ruled out) in this page load. Outside the component:
 * a remount used to start from an empty set and announce every entry again.
 */
const deliveries = new WeakMap<
  Store,
  Map<number, { done: Set<string>; pending: Set<string> }>
>();

function deliveryFor(store: Store) {
  const generation = store.getIdentityGeneration();
  let sessions = deliveries.get(store);
  if (!sessions) deliveries.set(store, (sessions = new Map()));
  let state = sessions.get(generation);

  if (!state) {
    sessions.clear();
    sessions.set(generation, (state = { done: new Set(), pending: new Set() }));
  }

  return state;
}

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
 * when you're already looking at the conversation. Historical messages are
 * reconciled into the durable inbox without replaying alerts. Renders nothing.
 */
export function MessageNotifier(): null {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const [currentSubject] = useCurrentSubject();
  const { activePanel, selectedMeeting, setPanelOpen } = useRightPanel();
  const { followedSession, activeMeeting } = useFollow();
  // The meeting chat in the right panel, when it is open (as the panel picks it).
  const panelChat =
    activePanel === 'followSession'
      ? (selectedMeeting ?? followedSession ?? activeMeeting)
      : undefined;
  const navigate = useNavigateWithTransition();
  const { privateDrive } = usePrivateDrive();
  const [sharedWithMe] = usePrivateDriveList(core.properties.sharedWithMe);

  // Toasts on screen, so opening the meeting panel can take them away.
  const shown = useRef(new Set<string>());
  const meetingPanelOpen = activePanel === 'followSession';

  useEffect(() => {
    if (!meetingPanelOpen) return;

    shown.current.forEach(id => toast.dismiss(id));
    shown.current.clear();
  }, [meetingPanelOpen]);
  // Announced while away, with system notifications not decided yet.
  const missed = useRef(0);
  // Inbox writes still in flight, per target, so reading waits for them.
  const recording = useRef(new Map<string, Promise<unknown>>());

  const readAbout = useEffectEvent((target: string, upTo = Date.now()) => {
    if (!privateDrive) return;
    const generation = store.getIdentityGeneration();

    const pending = recording.current.get(target) ?? Promise.resolve();

    void pending
      .then(() => {
        if (store.getIdentityGeneration() === generation)
          return markReadAbout(store, privateDrive, target, upTo);
      })
      .catch(e => {
        if (!(e instanceof RequestCancelledError))
          console.error('Could not mark notifications read:', e);
      });
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

    // The meeting chat is open beside the page: its messages are on screen
    // whatever the page is.
    if (
      panelChat &&
      store.normalizeSubject(panelChat) === store.normalizeSubject(n.target)
    ) {
      return true;
    }

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
    async (facts: MessageFacts, text: string): Promise<boolean> => {
      const generation = store.getIdentityGeneration();
      const subject = facts.subject;
      const ctx = { me: agent?.subject, since: 0 };

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
        isLocalOnly: s => !!demoForDrive(store.driveOfSubject(s)),
        creatorOf: s => {
          const entry = parseEntryId(s);

          return entry
            ? related.get(entry.page)?.getChatLogEntry(entry.key)?.a
            : related.get(s)?.getCreatedBy();
        },
      });

      if (store.getIdentityGeneration() !== generation) return false;
      if (!related.has(facts.about ?? facts.parent ?? '')) return false;
      if (!n) return true;
      const looking = isLookingAt(n);

      if (looking) {
        // Another open device may still record it; read that copy too.
        const seenAt = Date.now();
        setTimeout(() => {
          if (store.getIdentityGeneration() === generation)
            readAbout(n.target, seenAt);
        }, 3000);
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
          read: looking,
        });
        const all = Promise.all([before, record]);
        recording.current.set(n.target, all);
        void all
          .finally(() => {
            if (recording.current.get(n.target) === all) {
              recording.current.delete(n.target);
            }
          })
          .catch(() => {});
        await record;
      }

      if (!privateDrive || store.getIdentityGeneration() !== generation)
        return false;
      // Catch-up records old messages quietly; replay never creates popup storms.
      if (looking || (facts.createdAt ?? 0) < APP_STARTED) return true;

      if (!document.hidden && document.hasFocus()) {
        // The meeting panel covers or crowds the page and has its own chat
        // open; a bubble over its message box is noise. Still in the Inbox.
        if (meetingPanelOpen) return true;

        shown.current.add(bubbleId(n.target));
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
          { duration: 6000, id: bubbleId(n.target) },
        );

        return true;
      }

      if (shouldOfferOsNotifications()) missed.current += 1;

      showOsNotification({
        title,
        body,
        tag: bubbleId(n.target),
        onClick: () => open(n),
      });

      return true;
    },
  );

  const onUpdate = useEffectEvent(async (resource: Resource) => {
    if (!agent?.subject || !privateDrive) return;
    const page = resource.stable;
    const classes =
      (page.get(core.properties.isA) as string[] | undefined) ?? [];
    const ctx = { me: agent.subject, since: 0 };
    if (demoForDrive(store.driveOfSubject(page.subject))) return;
    const delivery = deliveryFor(store);
    const candidates = classes.includes(dataBrowser.classes.chatLog)
      ? page.listChatLogEntries().map(({ key, entry }) => ({
          facts: entryFacts(page.subject, factsOf(page), key, entry),
          text: entry.t,
        }))
      : [
          {
            facts: factsOf(page),
            text:
              (page.get(core.properties.description) as string | undefined) ??
              '',
          },
        ];

    for (const { facts, text } of candidates) {
      const source = notificationSourceId(facts.subject);
      if (delivery.done.has(source) || delivery.pending.has(source)) continue;
      const candidate = isCandidate(facts, ctx);
      if (candidate === undefined) continue;

      if (!candidate) {
        delivery.done.add(source);
        continue;
      }

      delivery.pending.add(source);
      await announce(facts, text)
        .then(complete => {
          if (complete) delivery.done.add(source);
        })
        .finally(() => {
          // A failed inbox write remains retryable on resume or another update.
          delivery.pending.delete(source);
        });
    }
  });

  useEffect(() => {
    if (!agent?.subject || !privateDrive) return;
    let stopped = false;
    let running = false;
    const generation = store.getIdentityGeneration();

    const scan = async () => {
      try {
        // Include resources loaded before this component mounted, and changes
        // imported from Vault while another drive is selected.
        for (const resource of [...store.resources.values()]) {
          if (stopped || store.getIdentityGeneration() !== generation) return;
          await onUpdate(resource);
        }

        const drive = store.getDrive();
        if (!drive || demoForDrive(drive)) return;

        for (const cls of [
          dataBrowser.classes.message,
          dataBrowser.classes.chatLog,
        ]) {
          const collection = new CollectionBuilder(store)
            .setDrive(drive)
            .setProperty(core.properties.isA)
            .setValue(cls)
            .setPageSize(100)
            .build();
          await collection.waitForReady();
          const subjects = await collection.getAllMembers();

          for (const subject of subjects) {
            if (stopped || store.getIdentityGeneration() !== generation) return;
            const resource = await store.getResource(subject);
            if (stopped || store.getIdentityGeneration() !== generation) return;
            if (!resource.error) await onUpdate(resource);
          }
        }
      } catch (error) {
        if (!stopped && store.getIdentityGeneration() === generation)
          console.warn('Notification catch-up will retry:', error);
      }
    };

    const resume = () => {
      if (running || stopped || store.getIdentityGeneration() !== generation)
        return;
      running = true;
      void scan().finally(() => {
        running = false;
      });
    };

    const off = store.on(StoreEvents.DriveChanged, resume);
    window.addEventListener('online', resume);
    window.addEventListener('focus', resume);
    const timer = setInterval(resume, 60_000);
    resume();

    return () => {
      stopped = true;
      off();
      clearInterval(timer);
      window.removeEventListener('online', resume);
      window.removeEventListener('focus', resume);
    };
  }, [store, agent?.subject, privateDrive]);

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
        void onUpdate(resource).catch(e => {
          if (!(e instanceof RequestCancelledError))
            console.error('Could not show a notification:', e);
        });
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
