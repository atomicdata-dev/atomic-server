import { useMediaQuery } from '../../hooks/useMediaQuery';
import { useSettings } from '../../helpers/AppSettings';
import { styled } from 'styled-components';
import { transition } from '../../helpers/transition';

export function OverlapSpacer(): JSX.Element {
  const narrow = useMediaQuery('(max-width: 950px)');
  const { navbarFloating } = useSettings();
  const elivate = narrow && navbarFloating;

  return <Elivator $elivate={elivate} />;
}

const Elivator = styled.div<{ $elivate: boolean }>`
  height: ${p => (p.$elivate ? '3.5rem' : '0rem')};
  ${transition('height')}
`;
