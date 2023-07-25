export function truncateMarkdown(value: string, length: number): string {
  if (value.length <= length) {
    return value;
  }

  const head = value.slice(0, length);

  if (head.endsWith('\n')) {
    return head + '...';
  }

  const tail = value.slice(length);
  const firstNewLine = tail.indexOf('\n');

  return (
    value.slice(
      0,
      length + (firstNewLine === -1 ? tail.length : firstNewLine),
    ) + '...'
  );
}

export function markdownToPlainText(markdownString: string): string {
  // Remove markdown characters
  let plainText = markdownString.replace(/#+/g, '');
  plainText = plainText.replace(/\*+/g, '');
  plainText = plainText.replace(/_+/g, '');
  plainText = plainText.replace(/`+/g, '');
  plainText = plainText.replace(/~+/g, '');

  // Remove links
  plainText = plainText.replace(/\[(.*?)\]\((.*?)\)/g, '$1');

  return plainText;
}
