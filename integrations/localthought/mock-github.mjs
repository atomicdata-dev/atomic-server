/** Stateful provider fixture, shared by the HTTP proxy and its test-side driver. */
export function githubTracker() {
  const repositories = new Map();
  const repo = name => {
    if (!repositories.has(name))
      repositories.set(name, { issues: [], comments: [] });
    return repositories.get(name);
  };
  let id = 0;
  const now = () => new Date().toISOString();
  const api = {
    snapshot: name => structuredClone(repo(name)),
    createIssue(name, input) {
      const state = repo(name);
      const number = state.issues.length + 1;
      const issue = {
        id: ++id,
        number,
        title: input.title,
        body: input.body ?? '',
        state: 'open',
        labels: [],
        url: `https://api.github.com/repos/${name}/issues/${number}`,
        html_url: `https://github.com/${name}/issues/${number}`,
        user: { login: 'mock-user' },
        created_at: now(),
        updated_at: now(),
      };
      state.issues.push(issue);
      return structuredClone(issue);
    },
    updateIssue(name, number, input) {
      const issue = repo(name).issues.find(i => i.number === number);
      if (!issue) return;
      for (const field of ['title', 'body', 'state', 'labels'])
        if (input[field] !== undefined) issue[field] = input[field];
      issue.updated_at = now();
      return structuredClone(issue);
    },
    createComment(name, number, input) {
      if (!repo(name).issues.some(i => i.number === number)) return;
      const comment = {
        id: ++id,
        body: input.body,
        issue_url: `https://api.github.com/repos/${name}/issues/${number}`,
        user: { login: 'mock-commenter' },
        created_at: now(),
        updated_at: now(),
      };
      repo(name).comments.push(comment);
      return structuredClone(comment);
    },
    request(method, url, input = {}) {
      const match = url.pathname.match(
        /^\/proxy\/github-issues\/repos\/([^/]+\/[^/]+)\/issues(?:\/(.*))?$/,
      );
      if (!match) return { status: 404, body: {} };
      const [, name, tail = ''] = match;
      const state = repo(name);
      const page = Number(url.searchParams.get('page') ?? 1);
      const size = Number(url.searchParams.get('per_page') ?? 100);
      const paginate = rows => rows.slice((page - 1) * size, page * size);
      let value;
      if (!tail) {
        if (method === 'GET') value = paginate(state.issues);
        if (method === 'POST') value = api.createIssue(name, input);
      } else if (/^comments\/\d+$/.test(tail)) {
        const comment = state.comments.find(
          c => c.id === Number(tail.split('/')[1]),
        );
        if (method === 'GET') value = comment;
        if (method === 'PATCH' && comment)
          value = Object.assign(comment, {
            body: input.body,
            updated_at: now(),
          });
      } else {
        const [numberText, resource, label] = tail.split('/');
        const number = Number(numberText);
        const issue = state.issues.find(i => i.number === number);
        if (issue && !resource) {
          if (method === 'GET') value = issue;
          if (method === 'PATCH') value = api.updateIssue(name, number, input);
        } else if (issue && resource === 'comments') {
          if (method === 'GET')
            value = paginate(
              state.comments.filter(c => c.issue_url === issue.url),
            );
          if (method === 'POST') value = api.createComment(name, number, input);
        } else if (issue && resource === 'labels') {
          if (method === 'POST')
            value = issue.labels = [
              ...new Set([...issue.labels, ...input.labels]),
            ];
          if (method === 'DELETE')
            value = issue.labels = issue.labels.filter(
              l => l !== decodeURIComponent(label),
            );
        }
      }
      return {
        status: value === undefined ? 404 : method === 'POST' ? 201 : 200,
        body: structuredClone(value ?? {}),
      };
    },
  };
  return api;
}
