const SUBJECT = /(?:https?:\/\/|did:ad:|atomic:)[^\s"'<>)\]]+/g;

/**
 * Cuts long subject URLs (`https://…`, `did:ad:…`, `atomic:…`) down to their
 * start and end, so an error message stays readable. Display only: whoever
 * copies the message should still get the full text.
 */
export function shortenSubjects(text: string, max = 36): string {
  return text.replace(SUBJECT, url => {
    if (url.length <= max) return url;

    const head = Math.ceil((max - 1) * 0.6);
    const tail = max - 1 - head;

    return `${url.slice(0, head)}…${url.slice(-tail)}`;
  });
}
