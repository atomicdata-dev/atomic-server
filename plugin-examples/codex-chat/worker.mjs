import { Codex } from './protocol.mjs';
import { core, reduceEvent, approvalChoices } from './model.mjs';
import { children } from './atomic.ts';
import { readFile, writeFile, open, unlink, rename } from 'node:fs/promises';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function work(store, config, file, options = {}) {
  const listChildren = options.children || children;
  const p = config.properties;
  let journal;
  try {
    journal = JSON.parse(await readFile(file + '.journal', 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    journal = { seen: [], threads: {} };
  }
  if (
    !Array.isArray(journal.seen) ||
    !journal.threads ||
    typeof journal.threads !== 'object'
  )
    throw new Error('Invalid worker journal; restore it before continuing');
  const lock = await open(file + '.lock', 'wx', 0o600);
  await lock.writeFile(String(process.pid));
  const codex = options.codex || new Codex();
  const persist = async () => {
    await writeFile(file + '.journal.tmp', JSON.stringify(journal), {
      mode: 0o600,
    });
    await rename(file + '.journal.tmp', file + '.journal');
  };
  const set = async (resource, values) => {
    for (const [key, value] of Object.entries(values))
      await resource.set(p[key], value);
    await resource.save();
  };
  let stopping = false,
    active,
    fatal;
  const stop = () => {
    stopping = true;
    codex.close();
  };
  options.signal?.addEventListener('abort', stop, { once: true });
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let events = Promise.resolve();
  codex.on('closed', error => {
    fatal = error;
  });
  codex.on('message', message => {
    events = events
      .then(async () => {
        const { method, params = {}, id } = message;
        if (!active || params.threadId !== active.threadId) {
          if (id !== undefined)
            codex.send({
              id,
              error: {
                code: -32601,
                message: 'Request is not supported by this chat client',
              },
            });
          return;
        }
        if (id !== undefined) {
          const choices = approvalChoices(method, params);
          if (!choices.length) {
            codex.send({
              id,
              error: {
                code: -32601,
                message:
                  'This input type is not supported; stop and continue in Codex',
              },
            });
            return;
          }
          const approval = await store.newResource({
            parent: active.resource.subject,
            isA: [config.approvalClass],
            propVals: {
              [core + 'name']: method.includes('command')
                ? 'Run command?'
                : 'Apply file changes?',
              [p.request]: { method, params, choices },
              [p.created]: Date.now(),
            },
          });
          await approval.save();
          active.approvals.push({ resource: approval, id, choices });
        } else if (method === 'turn/started') active.turnId = params.turn.id;
        else if (method === 'turn/completed') {
          active.state = params.turn.status;
          active.error = params.turn.error?.message;
          active.done = true;
        } else if (method === 'serverRequest/resolved') {
          active.approvals = active.approvals.filter(
            x => x.id !== params.requestId,
          );
        } else {
          active.items = reduceEvent(active.items, method, params);
          active.dirty = true;
        }
      })
      .catch(error => {
        fatal = error;
      });
  });
  try {
    await codex.initialize();
    // An accepted prompt can have side effects. A restart never resends it.
    for (const conversation of await listChildren(
      store,
      config.drive,
      config.data,
    )) {
      for (const turn of await listChildren(
        store,
        config.drive,
        conversation.subject,
      )) {
        if (
          turn.get(p.state) === 'running' ||
          (turn.get(p.state) === 'queued' &&
            journal.seen.includes(turn.subject))
        )
          await set(turn, {
            state: 'uncertain',
            error:
              'Worker restarted. Check the Codex task before continuing; this prompt was not replayed.',
          });
      }
    }
    console.log(
      'Codex worker ready. Only this app and its configured workspace are connected.',
    );
    let heartbeat = 0;
    while (!stopping) {
      if (fatal) throw fatal;
      if (Date.now() - heartbeat > 5000) {
        await set(await store.getResource(config.app), {
          heartbeat: Date.now(),
        });
        heartbeat = Date.now();
      }
      if (active) {
        await events;
        const controls = await listChildren(
          store,
          config.drive,
          active.resource.subject,
        );
        if (
          !active.cancelled &&
          controls.some(x => x.get(p.cancel) === true) &&
          active.turnId
        ) {
          active.cancelled = true;
          await codex.request('turn/interrupt', {
            threadId: active.threadId,
            turnId: active.turnId,
          });
        }
        for (const approval of active.approvals.slice()) {
          await approval.resource.refresh();
          const answer = approval.resource.get(p.answer);
          if (!approval.choices.includes(answer)) continue;
          codex.send({ id: approval.id, result: { decision: answer } });
          active.approvals = active.approvals.filter(x => x !== approval);
        }
        await events;
        if (active.dirty || active.done) {
          // Events can arrive while save awaits the server. Only retire a turn
          // after its terminal state was included in this exact write.
          const finished = active.done,
            items = active.items;
          await set(active.resource, {
            transcript: items,
            ...(finished
              ? { state: active.state || 'failed', error: active.error || '' }
              : {}),
          });
          active.dirty = active.items !== items;
          if (finished) active = undefined;
        }
      } else {
        const conversations = await listChildren(
          store,
          config.drive,
          config.data,
        );
        for (const conversation of conversations) {
          if (!(conversation.get(core + 'isA') || []).includes(config.rowClass))
            continue;
          const turns = (
            await listChildren(store, config.drive, conversation.subject)
          )
            .filter(x => (x.get(core + 'isA') || []).includes(config.turnClass))
            .sort(
              (a, b) =>
                Number(a.get(p.created)) - Number(b.get(p.created)) ||
                a.subject.localeCompare(b.subject),
            );
          // Explicitly stop a conversation after uncertain execution.
          if (turns.some(x => x.get(p.state) === 'uncertain')) continue;
          const turn = turns.find(
            x =>
              x.get(p.state) === 'queued' && !journal.seen.includes(x.subject),
          );
          if (!turn) continue;
          const prompt = turn.get(p.prompt);
          if (
            typeof prompt !== 'string' ||
            !prompt.trim() ||
            prompt.length > 100000
          ) {
            await set(turn, {
              state: 'failed',
              error: 'Prompt must contain 1–100,000 characters.',
            });
            continue;
          }
          journal.seen.push(turn.subject);
          await persist(); // At most once, even if the next process dies before Atomic saves.
          await set(turn, { state: 'running' });
          try {
            const savedThread = journal.threads[conversation.subject];
            const options = {
              cwd: config.workspace,
              approvalPolicy: 'on-request',
              approvalsReviewer: 'user',
              sandbox: 'read-only',
            };
            const result = await codex.request(
              savedThread ? 'thread/resume' : 'thread/start',
              savedThread ? { ...options, threadId: savedThread } : options,
            );
            const threadId = result.thread.id;
            journal.threads[conversation.subject] = threadId;
            await persist();
            await set(conversation, { thread: threadId });
            active = {
              resource: turn,
              threadId,
              items: [],
              approvals: [],
              dirty: false,
              done: false,
            };
            const started = await codex.request('turn/start', {
              threadId,
              input: [{ type: 'text', text: prompt }],
            });
            active.turnId = started.turn.id;
          } catch (error) {
            await set(turn, { state: 'uncertain', error: error.message });
            active = undefined;
          }
          break;
        }
      }
      await delay(options.pollMs ?? 500);
    }
  } finally {
    codex.close();
    if (active)
      await set(active.resource, {
        state: 'uncertain',
        error: 'Worker disconnected. This prompt will not be replayed.',
      }).catch(() => {});
    await lock.close();
    await unlink(file + '.lock');
    options.signal?.removeEventListener('abort', stop);
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
