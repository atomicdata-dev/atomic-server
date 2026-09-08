// @wc-ignore-file
import type { AIAsk } from '@components/AI/AISidebarContext';

export function editIntegrationAssistant(
  subject: string,
  table?: string,
): AIAsk {
  return {
    prompt:
      'Help me edit this integration. Start by asking what I would like to change: its workspace views, behavior, or code. Inspect the attached resources before proposing changes. Use the existing integration and table rather than creating replacements. Never ask me to paste credentials into chat. Explain and test proposed behavior changes before enabling them.',
    context: [subject, ...(table ? [table] : [])].map(resourceSubject => ({
      type: 'atomic-resource',
      subject: resourceSubject,
      id: crypto.randomUUID(),
    })),
  };
}
