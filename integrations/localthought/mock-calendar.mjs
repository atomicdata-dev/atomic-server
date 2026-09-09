/** Synthetic Google Calendar fixtures. No real calendar data or provider writes. */
const string = { type: 'string' };
const dateTime = {
  type: 'object',
  properties: {
    date: { ...string, format: 'date' },
    dateTime: { ...string, format: 'date-time' },
    timeZone: string,
  },
};
export const calendarDocument = {
  openapi: '3.0.3',
  info: { title: 'Synthetic Calendar', version: 'v3' },
  servers: [{ url: 'https://www.googleapis.com/calendar/v3' }],
  paths: {
    '/calendars/{calendarId}/events': {
      get: {
        parameters: [
          { name: 'calendarId', in: 'path', required: true, schema: string },
          ...['pageToken', 'timeMin', 'timeMax'].map(name => ({
            name,
            in: 'query',
            schema: string,
          })),
          { name: 'singleEvents', in: 'query', schema: { type: 'boolean' } },
          { name: 'showDeleted', in: 'query', schema: { type: 'boolean' } },
        ],
        'x-pagination': [{ scheme: 'pageToken' }],
        responses: {
          200: {
            description: 'Events',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    items: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/event' },
                    },
                    nextPageToken: string,
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  components: {
    paginationSchemes: {
      pageToken: {
        type: 'pageToken',
        request: { queryParameters: { pageToken: { role: 'pageToken' } } },
        response: { bodyFields: { nextPageToken: { role: 'nextPageToken' } } },
      },
    },
    schemas: {
      event: {
        type: 'object',
        properties: {
          id: string,
          summary: string,
          status: string,
          start: dateTime,
          end: dateTime,
          recurringEventId: string,
          htmlLink: string,
          attendees: {
            type: 'array',
            items: {
              type: 'object',
              properties: { email: string, responseStatus: string },
            },
          },
        },
      },
    },
    crudResources: {
      event: {
        schema: { $ref: '#/components/schemas/event' },
        identity: {
          urlTemplate: '/calendars/{calendarId}/events/{eventId}',
          bindings: { eventId: { field: 'id' } },
        },
        collections: {
          events: { urlTemplate: '/calendars/{calendarId}/events' },
        },
      },
    },
  },
};
export function calendarFixture(day = new Date().toISOString().slice(0, 10)) {
  const tomorrow = new Date(Date.parse(`${day}T00:00:00Z`) + 86400000)
    .toISOString()
    .slice(0, 10);
  const events = [
    {
      id: 'all-day',
      summary: 'Calendar all-day fixture',
      status: 'confirmed',
      start: { date: day },
      end: { date: tomorrow },
    },
    {
      id: 'timed',
      summary: 'Calendar timed fixture',
      status: 'confirmed',
      start: {
        dateTime: `${day}T00:30:00+02:00`,
        timeZone: 'Europe/Amsterdam',
      },
      end: { dateTime: `${day}T01:30:00+02:00`, timeZone: 'Europe/Amsterdam' },
      recurringEventId: 'series',
      originalStartTime: { dateTime: `${day}T00:30:00+02:00` },
      attendees: [
        { email: 'synthetic@example.com', responseStatus: 'accepted' },
      ],
    },
  ];
  const requests = [];
  return {
    events,
    requests,
    request(method, url) {
      requests.push({
        method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
      });
      if (method !== 'GET') return { status: 405, body: {} };
      if (
        !/^\/proxy\/google-calendar\/calendar\/v3\/calendars\/[^/]+\/events$/.test(
          url.pathname,
        )
      )
        return { status: 404, body: {} };
      // Both modes must request cancellation tombstones. Retained masters need
      // every exception, so applying date bounds in that mode is a data-loss bug.
      const series = url.searchParams.get('singleEvents') === 'false';
      if (
        url.searchParams.get('showDeleted') !== 'true' ||
        (series
          ? url.searchParams.has('timeMin') || url.searchParams.has('timeMax')
          : !url.searchParams.has('timeMin') || !url.searchParams.has('timeMax') || url.searchParams.get('singleEvents') !== 'true')
      ) return { status: 400, body: { error: 'Invalid recurrence query' } };
      const token = url.searchParams.get('pageToken');
      if (token && token !== 'second') return { status: 400, body: {} };
      return {
        status: 200,
        body: structuredClone(
          token
            ? { items: events.slice(1) }
            : { items: events.slice(0, 1), nextPageToken: 'second' },
        ),
      };
    },
  };
}
