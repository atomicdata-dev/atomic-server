// @wc-ignore-file
import { z } from 'zod';
import type { RunTrigger } from '@tomic/lib';

export const previewEventSchema = z.object({
  kind: z.enum([
    'manual',
    'cron',
    'timer',
    'webhook',
    'query',
    'query:entered',
    'query:left',
    'query:changed',
    'commit:before',
    'commit:after',
  ]),
  subject: z.string().optional(),
  id: z.string().optional(),
  edge: z.enum(['enter', 'leave']).optional(),
  at: z.number().int().nonnegative(),
  payload: z.json().optional(),
});
/** Event shape is test input only. The HTTP run endpoint supplies no worker authority. */
export function previewTrigger(
  sample: z.infer<typeof previewEventSchema> | undefined,
  subject: string,
  at: number,
): RunTrigger {
  return sample
    ? (previewEventSchema.parse(sample) as RunTrigger)
    : { kind: 'manual', subject, at };
}
