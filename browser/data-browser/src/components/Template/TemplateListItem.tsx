import { styled } from 'styled-components';

interface TemplateListItemProps {
  title: string;
  id: string;
  Image: React.FC;
  onClick: (id: string) => void;
}

export function TemplateListItem({
  title,
  id,
  onClick,
  Image,
}: TemplateListItemProps): React.JSX.Element {
  return (
    <Wrapper onClick={() => onClick(id)}>
      <Image />
      <Content>
        <span>{title}</span>
      </Content>
    </Wrapper>
  );
}

const Wrapper = styled.button`
  --template-color-bg: ${p => p.theme.colors.bg};
  --template-color-bg1: ${p => p.theme.colors.bg2};
  --template-color-bg2: ${p => p.theme.colors.textLight};

  appearance: none;
  padding: 0;
  cursor: pointer;
  background-color: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  overflow: clip;

  color: ${p => p.theme.colors.text};

  &:hover,
  &:focus-visible {
    border-color: ${p => p.theme.colors.main};
    --template-color-bg2: ${p => p.theme.colors.main};
  }

  & svg {
    width: 100%;
    height: auto;
  }
`;

const Content = styled.div`
  border-top: 1px solid ${p => p.theme.colors.bg2};
  padding: 1rem;
`;
