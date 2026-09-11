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
interface CalendarFixture {
  events: Array<{
    id: string;
    summary: string;
    recurrence?: string[];
    recurringEventId?: string;
    originalStartTime?: { date?: string; dateTime?: string; timeZone?: string };
    status: string;
    start: { date?: string; dateTime?: string; timeZone?: string };
    end: { date?: string; dateTime?: string; timeZone?: string };
  }>;
  requests: Array<{
    method: string;
    path: string;
    query: Record<string, string>;
  }>;
}
export function mockProxy(options?: {
  frontendOrigin?: string;
}): Server & { github: GitHubTracker; calendar: CalendarFixture };
