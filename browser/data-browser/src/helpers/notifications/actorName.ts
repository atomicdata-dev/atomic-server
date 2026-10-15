// @wc-ignore-file
/**
 * A name fit to show for an agent, or undefined. An agent without a name, or
 * one that isn't loaded, titles as its own subject; that is an address, not a
 * name. Callers supply their own (translated) fallback.
 */
export function actorName(
  title: string | undefined,
  subject?: string,
): string | undefined {
  const name = title?.trim();

  if (
    !name ||
    name === subject ||
    name.startsWith('atomic:agent:') ||
    name.startsWith('did:ad:')
  ) {
    return undefined;
  }

  return name;
}
