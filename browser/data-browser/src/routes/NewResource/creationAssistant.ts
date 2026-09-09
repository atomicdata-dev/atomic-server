// @wc-ignore-file
import type { AIAsk } from '../../components/AI/AISidebarContext';

export function creationAssistantAsk(request: string, parent: string): AIAsk {
  return {
    prompt: `${request.trim()}\n\nCreate this inside the attached parent resource. Reuse suitable existing templates and schema properties where possible. Ask about missing requirements before creating anything that depends on them.`,
    context: [
      { type: 'atomic-resource', subject: parent, id: crypto.randomUUID() },
    ],
  };
}
