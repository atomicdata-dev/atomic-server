// @wc-ignore-file
import type { AIAsk } from '@components/AI/AISidebarContext';
import type { IntegrationEvent } from './integrationAutomation';

/** Explicit draft context; never include host credentials or provider records. */
export function automationAssistantAsk(
  request: string,
  draft: string,
  integration: string,
  event: IntegrationEvent,
): AIAsk {
  return {
    prompt: [
      `Help me build this automation: ${request.trim()}`,
      '',
      'Update the attached automation draft using the attached integration.',
      `When: ${event.name}. ${event.description}`,
      'Ask me about any missing destinations or conditions. Check what this integration supports.',
      'Test the automation and explain when it runs, its conditions and its actions, with sample results. If no matching record exists, help me sync one first.',
      'Leave reviewing changes and enabling it to me. Keep the integration sync schedule unchanged.',
    ].join('\n'),
    context: [draft, integration].map(subject => ({
      type: 'atomic-resource',
      subject,
      id: crypto.randomUUID(),
    })),
  };
}

/** Start with the user's intent, before creating any draft or trigger. */
export function newAutomationAssistantAsk(
  drive: string,
  connections: string[],
  workspace?: string,
): AIAsk {
  return {
    prompt: [
      'Help me create a new automation.',
      ...(workspace
        ? [
            `The workspace is ${workspace}. Keep its existing data and views. Associate the automation with this workspace; a connection is optional.`,
          ]
        : []),
      'Start by asking what I would like to automate. Do not create anything until I describe the behavior.',
      'The attached resources are my drive, optional workspace and available connections, not a request to use all of them. If one connection is attached, use it as the suggested starting point.',
      'Once I describe the goal, inspect the relevant connections and supported events and actions. Ask about missing conditions or destinations; do not invent capabilities.',
      'Create an independent JavaScript automation referencing the selected integrations. Explain when it runs and what it does, test a sample, and leave applying changes and enabling automatic execution to me. Keep integration sync settings unchanged.',
    ].join('\n'),
    context: [
      ...new Set([drive, ...(workspace ? [workspace] : []), ...connections]),
    ].map(subject => ({
      type: 'atomic-resource',
      subject,
      id: crypto.randomUUID(),
    })),
  };
}
