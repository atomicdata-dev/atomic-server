import type { Server } from 'node:http';
interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: string;
  labels: string[];
}
interface Comment {
  id: number;
  body: string;
  issue_url: string;
}
interface GitHubTracker {
  snapshot(repository: string): { issues: Issue[]; comments: Comment[] };
  createIssue(
    repository: string,
    input: { title: string; body?: string },
  ): Issue;
  updateIssue(
    repository: string,
    number: number,
    input: Partial<Issue>,
  ): Issue | undefined;
  createComment(
    repository: string,
    number: number,
    input: { body: string },
  ): Comment | undefined;
}
export const tenantSecret: string;
export function mockProxy(options?: {
  frontendOrigin?: string;
}): Server & { github: GitHubTracker };
