const baseUrl = 'http://localhost:9883';

export const ontology = {
  classes: {
    program: baseUrl + '/o/Program',
    title: baseUrl + '/o/Title',
    paragraph: baseUrl + '/o/Paragraph',
    actionItem: baseUrl + '/o/ActionItem',
  },
  properties: {
    title: baseUrl + '/o/title',
    elements: baseUrl + '/o/elements',
    approvedOn: baseUrl + '/o/approvedOn',
    text: baseUrl + '/o/text',
    titleLevel: baseUrl + '/o/titleLevel',
  },
} as const;
