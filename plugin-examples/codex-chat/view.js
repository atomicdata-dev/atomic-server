/** Source-as-data view for feat/plugin-model. CONFIG is injected by the installer. */
export async function view({ root, store }) {
  const c = CONFIG,
    p = c.properties,
    core = 'https://atomicdata.dev/properties/';
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const style = el('style');
  style.textContent = `
    *{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,sans-serif;color:var(--font-color,#26332c);background:var(--bg,#fafbf9)}
    button,textarea{font:inherit}button{cursor:pointer;border:1px solid #d6ded7;border-radius:9px;padding:8px 13px;background:var(--bg,#fff);color:inherit}button:disabled{opacity:.5;cursor:default}
    .shell{display:grid;grid-template-columns:240px 1fr;min-height:90vh}.sidebar{border-right:1px solid #dce3db;padding:24px 16px;background:#eff3ed;color:#26332c}.brand{font-weight:650;font-size:22px;margin-bottom:4px}.subtle{font-size:12px;color:#65736b}.new{width:100%;margin:25px 0 14px}.conversation{display:block;text-align:left;width:100%;border:0;margin:4px 0;background:transparent;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.selected{background:#dce7d9;font-weight:600}
    .main{min-width:0;display:flex;flex-direction:column;height:94vh}.top{padding:20px 30px;border-bottom:1px solid #e0e6df;display:flex;justify-content:space-between;gap:15px}.messages{flex:1;overflow:auto;padding:30px max(24px,calc((100% - 790px)/2))}.empty{margin:12vh auto;max-width:460px}.empty h1{font-size:32px;line-height:1.2;font-weight:550}.message{margin-bottom:22px}.label{font-size:12px;font-weight:650;margin-bottom:5px;color:#69796d}.text{white-space:pre-wrap;overflow-wrap:anywhere}.user .text{background:#eaf0e6;padding:14px 18px;border-radius:14px;color:#26332c}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}details{border:1px solid #dce3db;border-radius:8px;padding:8px 12px;margin:8px 0}.approval{border:1px solid #c9ae70;background:#fff9e8;color:#483b21;border-radius:12px;padding:16px;margin:15px 0}.approval button{margin:6px 8px 0 0}.composer{padding:16px 24px 20px;border-top:1px solid #e0e6df}.input{display:flex;gap:10px;max-width:790px;margin:auto;align-items:flex-end}textarea{width:100%;resize:vertical;min-height:75px;max-height:220px;border:1px solid #ced8cc;border-radius:12px;padding:13px;background:var(--bg,#fff);color:inherit}.send{background:#294e39;color:white;border-color:#294e39}.error{color:#a12f26;font-size:13px;white-space:pre-wrap}.notice{max-width:790px;margin:8px auto 0;font-size:12px;color:#65736b}.status{font-size:12px}.stop{margin-left:8px}@media(max-width:650px){.shell{grid-template-columns:1fr}.sidebar{border-right:0;padding:12px}.sidebar .subtle,.brand{display:none}.new{margin:0 0 8px}.list{display:flex;overflow:auto}.conversation{width:auto;max-width:180px;flex-shrink:0}.main{height:80vh}.top{padding:12px 20px}}
  `;
  root.append(style);
  const shell = el('div', undefined, 'shell'),
    sidebar = el('aside', undefined, 'sidebar');
  const brand = el('div', '✳ Codex', 'brand'),
    subtitle = el('div', 'Your conversations, connected.', 'subtle');
  const newButton = el('button', '+ New conversation', 'new'),
    list = el('nav', undefined, 'list');
  list.setAttribute('aria-label', 'Conversations');
  sidebar.append(brand, subtitle, newButton, list);
  const main = el('main', undefined, 'main'),
    top = el('header', undefined, 'top');
  const title = el('strong', 'New conversation'),
    status = el('span', 'Connecting…', 'status');
  top.append(title, status);
  const messages = el('section', undefined, 'messages');
  messages.setAttribute('aria-label', 'Messages');
  const form = el('div', undefined, 'composer'),
    input = el('div', undefined, 'input');
  const textarea = el('textarea');
  textarea.placeholder = 'Ask Codex…';
  textarea.setAttribute('aria-label', 'Message');
  textarea.maxLength = 100000;
  const send = el('button', 'Send', 'send');
  send.type = 'button';
  const stop = el('button', 'Stop', 'stop');
  stop.type = 'button';
  stop.hidden = true;
  input.append(textarea, send, stop);
  const notice = el(
    'div',
    'Saved in Atomic · Runs in your configured local workspace',
    'notice',
  );
  const errorBox = el('div', '', 'error');
  errorBox.setAttribute('role', 'alert');
  form.append(input, notice, errorBox);
  main.append(top, messages, form);
  shell.append(sidebar, main);
  root.append(shell);
  let selected,
    activeTurn,
    busy = false,
    submitting = false,
    loading = false,
    pending = false,
    snapshot = '',
    generation = 0;
  const report = error => {
    errorBox.textContent = error.message || String(error);
  };
  const children = async parent =>
    Promise.all(
      (await store.query({ property: core + 'parent', value: parent })).map(s =>
        store.getResource(s),
      ),
    );
  async function create(parent, isA, values) {
    // The view protocol's create operation already persists the resource.
    // Do not re-save a possibly stale host snapshot immediately after creation.
    return store.newResource({ parent, isA, propVals: values });
  }
  function select(subject) {
    selected = subject;
    generation++;
    snapshot = '';
    errorBox.textContent = '';
    void refresh().catch(report);
  }
  newButton.onclick = () => {
    select(undefined);
    textarea.focus();
  };
  function bubble(label, text, kind = '') {
    const box = el('article', undefined, 'message ' + kind);
    box.append(el('div', label, 'label'), el('div', text, 'text'));
    return box;
  }
  async function refresh() {
    if (loading) {
      pending = true;
      return;
    }
    loading = true;
    const version = generation,
      current = selected;
    try {
      const conversations = (await children(c.data)).filter(x =>
        (x.get(core + 'isA') || []).includes(c.rowClass),
      );
      const app = await store.getResource(c.app);
      const online = Date.now() - Number(app.get(p.heartbeat) || 0) < 15000;
      const turns = current
        ? (await children(current))
            .filter(x => (x.get(core + 'isA') || []).includes(c.turnClass))
            .sort(
              (a, b) =>
                Number(a.get(p.created)) - Number(b.get(p.created)) ||
                a.subject.localeCompare(b.subject),
            )
        : [];
      const approvals = current
        ? (
            await Promise.all(
              turns
                .filter(t => t.get(p.state) === 'running')
                .map(t => children(t.subject)),
            )
          )
            .flat()
            .filter(x => x.get(p.request))
        : [];
      if (version !== generation) return;
      list.replaceChildren();
      for (const conversation of conversations.reverse()) {
        const b = el(
          'button',
          String(conversation.get(core + 'name') || 'Conversation'),
          'conversation' +
            (conversation.subject === current ? ' selected' : ''),
        );
        b.onclick = () => select(conversation.subject);
        list.append(b);
      }
      title.textContent =
        conversations.find(x => x.subject === current)?.get(core + 'name') ||
        'New conversation';
      status.textContent = online ? '● Worker connected' : '○ Worker offline';
      activeTurn = turns.find(t => t.get(p.state) === 'running');
      busy =
        !!activeTurn ||
        turns.some(t => ['queued', 'uncertain'].includes(t.get(p.state)));
      send.disabled = busy || submitting;
      stop.hidden = !activeTurn;
      const next = JSON.stringify([
        current,
        turns.map(x => x.props),
        approvals.map(x => x.props),
      ]);
      if (next === snapshot) return;
      snapshot = next;
      const atBottom =
        messages.scrollHeight - messages.scrollTop - messages.clientHeight <
        100;
      messages.replaceChildren();
      if (!turns.length) {
        const empty = el('div', undefined, 'empty');
        empty.append(
          el('div', '✳', 'brand'),
          el('h1', 'What would you like to work on?'),
          el(
            'p',
            'Start a conversation with Codex. Your messages and replies stay linked here in Atomic.',
          ),
        );
        messages.append(empty);
      }
      for (const turn of turns) {
        messages.append(
          bubble('You', String(turn.get(p.prompt) || ''), 'user'),
        );
        for (const item of turn.get(p.transcript) || []) {
          if (item.type === 'agentMessage')
            messages.append(bubble('Codex', item.text || ''));
          else if (
            ['commandExecution', 'fileChange', 'mcpToolCall'].includes(
              item.type,
            )
          ) {
            const detail = el('details');
            detail.append(
              el('summary', item.command || item.tool || 'File changes'),
              el(
                'pre',
                item.aggregatedOutput ||
                  JSON.stringify(item.changes || item.result || {}, null, 2),
              ),
            );
            messages.append(detail);
          }
        }
        const state = turn.get(p.state);
        if (state !== 'completed')
          messages.append(
            el(
              'p',
              state === 'queued'
                ? 'Queued · waiting for the local worker'
                : state === 'running'
                  ? 'Codex is working…'
                  : String(state),
              'subtle',
            ),
          );
        if (turn.get(p.error))
          messages.append(el('p', String(turn.get(p.error)), 'error'));
      }
      for (const approval of approvals) {
        if (approval.get(p.answer)) continue;
        const request = approval.get(p.request),
          box = el('div', undefined, 'approval');
        box.append(
          el('strong', String(approval.get(core + 'name'))),
          el('pre', JSON.stringify(request.params, null, 2)),
        );
        for (const choice of request.choices) {
          const b = el(
            'button',
            choice === 'accept' ? 'Approve once' : 'Decline',
          );
          b.onclick = async () => {
            b.disabled = true;
            try {
              approval.set(p.answer, choice);
              await approval.save();
              snapshot = '';
              await refresh();
            } catch (error) {
              b.disabled = false;
              report(error);
            }
          };
          box.append(b);
        }
        messages.append(box);
      }
      if (atBottom) messages.scrollTop = messages.scrollHeight;
    } finally {
      loading = false;
      if (pending) {
        pending = false;
        void refresh().catch(report);
      }
    }
  }
  const submit = async event => {
    event.preventDefault();
    const prompt = textarea.value.trim();
    if (!prompt || busy || submitting) return;
    submitting = true;
    busy = true;
    send.disabled = true;
    errorBox.textContent = '';
    try {
      let parent = selected;
      if (!parent) {
        const conversation = await create(c.data, [c.rowClass], {
          [core + 'name']: prompt.slice(0, 70),
          [p.created]: Date.now(),
        });
        parent = conversation.subject;
        selected = parent;
        generation++;
      }
      await create(parent, [c.turnClass], {
        [core + 'name']: 'Message',
        [p.prompt]: prompt,
        [p.created]: Date.now(),
        [p.state]: 'queued',
      });
      textarea.value = '';
      snapshot = '';
      await refresh();
    } catch (error) {
      report(error);
      busy = false;
    } finally {
      submitting = false;
      send.disabled = busy;
    }
  };
  send.onclick = submit;
  textarea.onkeydown = event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      void submit(event);
    }
  };
  stop.onclick = async () => {
    if (!activeTurn) return;
    stop.disabled = true;
    try {
      await create(activeTurn.subject, [], {
        [core + 'name']: 'Stop request',
        [p.cancel]: true,
      });
    } catch (error) {
      report(error);
    } finally {
      stop.disabled = false;
    }
  };
  await refresh();
  const timer = setInterval(() => {
    if (!root.isConnected) clearInterval(timer);
    else void refresh().catch(report);
  }, 1000);
}
