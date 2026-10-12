import type { ReactNode } from 'react';
import { css, styled, type DefaultTheme } from 'styled-components';
import { FaCheck } from 'react-icons/fa6';
import {
  ServiceBody,
  ServiceDescription,
  ServiceIcon,
  ServiceSection,
  ServiceTitle,
} from '@tomic/service-ui';
import '@tomic/service-ui/styles.css';
import {
  CARD_ACTIONS_GAP,
  CARD_SUB_FONT,
  CARD_TITLE_FONT,
} from '../cardSurface';

/**
 * Where a service stands for the drive in view.
 *
 * - `current`: the step this drive is on.
 * - `included`: on, as part of the current step (Cloud Vault under Cloud Server).
 * - `offered`: someone made it available and it waits for you.
 */
export type ServiceStanding = 'current' | 'included' | 'offered';

/** The colour of the status dot: green on, blue working, amber waiting, red failed. */
export type ServiceTone = 'ok' | 'busy' | 'waiting' | 'error' | 'muted';

/**
 * One cloud service on the Sync page, in a fixed shape.
 *
 * Every service reads the same way, top to bottom: its name and where it
 * stands, what it is (the same sentence in every state), what you get while
 * it is off, how it is doing right now, and what you can do. State never
 * renames the service: "Cloud Vault" stays "Cloud Vault", and the status line
 * says whether it is backing up, waiting or failing.
 *
 * `details` carries usage and the like, between the status and the actions.
 * Actions go primary first, then subtle ones, so the button you are most
 * likely to want is always in the same place.
 */
export function ServiceRow({
  kind,
  title,
  standing,
  tagline,
  points,
  status,
  details,
  notice,
  actions,
  ...props
}: {
  kind: 'vault' | 'server';
  title: string;
  standing?: ServiceStanding | null;
  tagline: ReactNode;
  /** What you get. Shown only while the service is not on. */
  points?: string[];
  status?: { tone: ServiceTone; text: ReactNode } | null;
  /** What the service holds for this drive, such as its usage or its address.
   *  Sits under the status line, so every row shows it in the same place. */
  details?: ReactNode;
  /** Something to read before acting, such as what consent means. */
  notice?: ReactNode;
  actions?: ReactNode;
  [data: `data-${string}`]: string | number | undefined;
}) {
  const on = standing === 'current' || standing === 'included';

  return (
    <Row {...props}>
      <ServiceIcon kind={kind} active={on} />
      <Body>
        <TitleRow>
          <Title>{title}</Title>
          {standing && (
            <Badge $standing={standing} data-testid='service-standing'>
              {standing === 'current'
                ? 'Current'
                : standing === 'included'
                  ? 'Included'
                  : 'Offered'}
            </Badge>
          )}
        </TitleRow>
        <Tagline>{tagline}</Tagline>
        {!on && points && points.length > 0 && (
          <Points>
            {points.map(point => (
              <li key={point}>
                <FaCheck aria-hidden />
                <span>{point}</span>
              </li>
            ))}
          </Points>
        )}
        {status && (
          <StatusLine data-tone={status.tone}>
            <StatusDot $tone={status.tone} aria-hidden />
            <span>{status.text}</span>
          </StatusLine>
        )}
        {details && <Details>{details}</Details>}
        {notice && <Notice>{notice}</Notice>}
        {actions && <Actions>{actions}</Actions>}
      </Body>
    </Row>
  );
}

/** The rule between services, and their shared padding. */
export const ServiceRows = styled.div`
  --service-accent: ${p => p.theme.colors.main};
  --service-muted: ${p => p.theme.colors.textLight};
  --service-text: ${p => p.theme.colors.text};
  --service-neutral: ${p => p.theme.colors.bg1};

  & > * + * {
    border-top: 1px solid ${p => `${p.theme.colors.main}33`};
  }
`;

const Row = styled(ServiceSection)`
  display: flex;
  align-items: flex-start;
  gap: 0.9rem;
  padding: 0.9rem 1rem;
  min-width: 0;
`;

const Body = styled(ServiceBody)`
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  min-width: 0;
`;

const TitleRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
`;

const Title = styled(ServiceTitle)`
  margin: 0;
  font-size: ${CARD_TITLE_FONT};
  font-weight: 600;
`;

const Badge = styled.span<{ $standing: ServiceStanding }>`
  flex-shrink: 0;
  padding: 0.1rem 0.55rem;
  border-radius: 999px;
  font-size: 0.72rem;
  font-weight: 600;
  white-space: nowrap;
  border: 1px solid
    ${p =>
      p.$standing === 'offered' ? p.theme.colors.warning : p.theme.colors.main};
  color: ${p =>
    p.$standing === 'current'
      ? p.theme.colors.bg
      : p.$standing === 'offered'
        ? p.theme.colors.warning
        : p.theme.colors.main};
  background: ${p =>
    p.$standing === 'current' ? p.theme.colors.main : 'transparent'};
`;

const Tagline = styled(ServiceDescription)`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const Points = styled.ul`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin: 0.15rem 0;
  padding: 0;
  list-style: none;
  font-size: ${CARD_SUB_FONT};
  color: ${p => p.theme.colors.text};

  li {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    margin: 0;
    padding: 0;
  }

  svg {
    flex-shrink: 0;
    font-size: 0.7rem;
    color: ${p => p.theme.colors.main};
  }
`;

const StatusLine = styled.p`
  display: flex;
  align-items: flex-start;
  gap: 0.45rem;
  margin: 0;
  color: ${p => p.theme.colors.text};
  font-size: ${CARD_SUB_FONT};
`;

const TONE_COLOURS: Record<ServiceTone, (t: DefaultTheme) => string> = {
  ok: () => '#3fb950',
  busy: t => t.colors.main,
  waiting: t => t.colors.warning,
  error: t => t.colors.alert,
  muted: t => t.colors.textLight,
};

const StatusDot = styled.span<{ $tone: ServiceTone }>`
  flex-shrink: 0;
  /* Centred on the first line of text, however many lines follow. */
  margin-top: calc(0.5lh - 0.25rem);
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: ${p => TONE_COLOURS[p.$tone](p.theme)};
`;

/**
 * One compact size for every button inside a service row (its actions and its
 * details), whichever variant it is. Set here, once, so no call site picks its
 * own size.
 */
export const compactButtons = css`
  button {
    min-height: 0;
    padding: 0.25rem 0.7rem;
    font-size: 0.8rem;
    line-height: 1.3;
    white-space: nowrap;
    gap: 0.4ch;
  }
`;

const Details = styled.div`
  ${compactButtons}
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-width: 0;
  margin-top: 0.15rem;
`;

const Notice = styled.p`
  margin: 0.2rem 0 0;
  padding: 0.6rem 0.75rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.warning}66;
  background: ${p => p.theme.colors.warning}14;
  color: ${p => p.theme.colors.text};
  font-size: ${CARD_SUB_FONT};
  line-height: 1.4;
`;

const Actions = styled.div`
  ${compactButtons}
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: ${CARD_ACTIONS_GAP};
  margin-top: 0.3rem;
`;
