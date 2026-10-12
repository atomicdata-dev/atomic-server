import { visit } from 'unist-util-visit';
import { useMemo, FC } from 'react';
import { AtomicLink } from '../../AtomicLink';
import { useResource } from '@tomic/react';
import { styled } from 'styled-components';

interface MentionNode {
  type: 'mention';
  data: {
    hName: 'mention';
    hProperties: {
      id: string;
      label: string;
      variant?: 'skill';
    };
  };
}

interface TextNode {
  type: 'text';
  value: string;
}

interface ParentNode {
  children: (TextNode | MentionNode)[];
}

const parseMentionAttributes = (attributes: string) => {
  const parsed: Record<string, string> = {};
  const attrRegex = /([\w-]+)="([^"]*)"/g;
  let match;

  while ((match = attrRegex.exec(attributes)) !== null) {
    const [, key, value] = match;
    parsed[key] = value;
  }

  return parsed;
};

/**
 * A remark plugin that parses mentions like [@id="..." label="..."]
 */
export const remarkMention = () => {
  return (tree: unknown) => {
    visit(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      tree as any,
      'text',
      (node: TextNode, index: number | undefined, parent: ParentNode) => {
        const regex =
          /\[([@/])\s*([^\]]*id="[^"]+"[^\]]*label="[^"]+"[^\]]*)\]/g;
        const children: (TextNode | MentionNode)[] = [];
        let lastIndex = 0;
        let match;

        while ((match = regex.exec(node.value)) !== null) {
          const [fullMatch, prefix, attrs] = match;
          const {
            id,
            label,
            type,
            'data-type': dataType,
          } = parseMentionAttributes(attrs);
          const startIndex = match.index;

          if (startIndex > lastIndex) {
            children.push({
              type: 'text',
              value: node.value.slice(lastIndex, startIndex),
            });
          }

          children.push({
            type: 'mention',
            data: {
              hName: 'mention',
              hProperties: {
                id,
                label,
                variant:
                  prefix === '/' || type === 'skill' || dataType === 'skill'
                    ? 'skill'
                    : undefined,
              },
            },
          });

          lastIndex = startIndex + fullMatch.length;
        }

        if (lastIndex < node.value.length) {
          children.push({
            type: 'text',
            value: node.value.slice(lastIndex),
          });
        }

        if (children.length > 0 && parent && typeof index === 'number') {
          parent.children.splice(index, 1, ...children);
        }
      },
    );
  };
};

export interface MentionProps {
  id: string;
  label: string;
  variant?: 'skill';
}

/**
 * Component for rendering resource mentions in markdown. These mentions are primarily used by the AI chat.
 */
export const Mention: FC<MentionProps> = ({ id, label, variant }) => {
  const isSkill = variant === 'skill';
  const isAtomic = !isSkill && /^(https?:|did:ad:)/.test(id);
  const resource = useResource(isAtomic ? id : '');

  const displayLabel = useMemo(() => {
    if (isAtomic && resource.title) {
      return resource.title;
    }

    return label;
  }, [isAtomic, resource.title, label]);

  if (isSkill) {
    return <SkillMentionText>/{label}</SkillMentionText>;
  }

  if (isAtomic) {
    return (
      <MentionBadge as={AtomicLink} subject={id} clean>
        {displayLabel}
      </MentionBadge>
    );
  }

  return <MentionBadge>{displayLabel}</MentionBadge>;
};

const MentionBadge = styled.span`
  display: inline-flex;
  align-items: center;
  background-color: ${p => p.theme.colors.mainSelectedBg};
  border-radius: ${p => p.theme.radius};
  padding-inline: 4px;
  color: ${p => p.theme.colors.mainSelectedFg};
  border: 1px solid ${p => p.theme.colors.mainSelectedFg};
  font-size: 0.9em;
  text-decoration: none !important;
  vertical-align: middle;
  margin-inline: 0.2ch;

  &:hover {
    color: ${p => p.theme.colors.mainSelectedFg} !important;
    background-color: ${p => p.theme.colors.mainSelectedBg} !important;
    filter: brightness(1.1);
  }
`;

const SkillMentionText = styled.span`
  color: ${p => p.theme.colors.main};
`;
