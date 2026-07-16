import {
  core,
  forms,
  useCollection,
  useMemberFromCollection,
  useNumber,
  useStore,
  useString,
  type Collection,
  type Resource,
  type Store,
} from '@tomic/react';
import { CollectionBuilder } from '@tomic/lib';
import { useState, type JSX } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { FaDownload, FaLink, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { Button } from '@components/Button';
import { IconButton } from '@components/IconButton/IconButton';
import { Column, Row } from '@components/Row';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Card } from '@components/Card';
import { DropdownMenu, type DropdownItem } from '@components/Dropdown';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';

const ACCESS_PUBLIC = 'public';
const ACCESS_INVITE_ONLY = 'invite-only';

/** Matches the plan's "cap a batch at a few hundred" — bulk generation is N
 * owner-signed genesis commits through the outbox. */
const MAX_BATCH = 200;

/** Unambiguous lowercase alphabet (no 0/o, 1/l/i) — codes end up in URLs
 * people may read out loud or retype. */
const CODE_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const CODE_LENGTH = 10;

function generateInviteCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(CODE_LENGTH));

  return Array.from(bytes, b => CODE_ALPHABET[b % CODE_ALPHABET.length]).join(
    '',
  );
}

/** Outside the component so the async loop + error handling doesn't need a
 * try/catch inside a component body (React Compiler limitation). */
async function createInviteCodes(
  store: Store,
  formSubject: string,
  amount: number,
): Promise<void> {
  for (let i = 0; i < amount; i++) {
    const invite = await store.newResource({
      parent: formSubject,
      isA: forms.classes.formInviteCode,
      propVals: {
        [forms.properties.formCode]: generateInviteCode(),
      },
    });
    await invite.save();
  }
}

/** Fetches every invite code as plain data, independent of the paginated
 * `useCollection` used for on-screen rendering — export needs a one-shot
 * read of all members, not a per-row hook. */
async function collectInviteCodes(
  store: Store,
  formSubject: string,
): Promise<string[]> {
  const collection = await new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(formSubject)
    .setFilters([
      { property: core.properties.isA, value: forms.classes.formInviteCode },
    ])
    .buildAndFetch();

  const codes: string[] = [];

  for await (const subject of collection) {
    const invite = await store.getResource(subject);
    const code = invite.get(forms.properties.formCode) as string | undefined;

    if (code) {
      codes.push(code);
    }
  }

  return codes;
}

function downloadTextFile(content: string, filename: string): void {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

interface FormAccessSectionProps {
  resource: Resource;
}

/** "Form access" settings (Phase 6 "Private links"): public vs invite-only
 * mode, plus invite link management (generate, copy, revoke) when
 * invite-only. Codes are FormInviteCode resources, children of the Form —
 * hierarchy rights keep them readable by form editors only, and the server's
 * definition/submit endpoints enforce them (`server/src/forms.rs`). */
export function FormAccessSection({
  resource,
}: FormAccessSectionProps): JSX.Element {
  const [access, setAccess] = useString(resource, forms.properties.formAccess, {
    commit: true,
  });
  const inviteOnly = access === ACCESS_INVITE_ONLY;

  return (
    <Column gap="1rem">
      <Field label="Who can open this form">
        <Row gap="0.5rem" wrapItems>
          <Button
            subtle={inviteOnly}
            title="Anyone with the share link can view and submit"
            onClick={() => setAccess(ACCESS_PUBLIC)}
          >
            Anyone with the link
          </Button>
          <Button
            subtle={!inviteOnly}
            title="Only visitors with a valid, unused invite link can view and submit"
            onClick={() => setAccess(ACCESS_INVITE_ONLY)}
          >
            Invite only
          </Button>
        </Row>
      </Field>
      {inviteOnly ? (
        <InviteCodeManager resource={resource} />
      ) : (
        <Hint>
          Switch to invite only to hand out single-use invite links instead of
          one public link.
        </Hint>
      )}
    </Column>
  );
}

const ExportTrigger = buildDefaultTrigger(<FaDownload />, 'Export invite links');

function InviteCodeManager({ resource }: FormAccessSectionProps): JSX.Element {
  const store = useStore();
  const [slug] = useString(resource, forms.properties.formPublishId);
  const [amount, setAmount] = useState<string>();
  const [generating, setGenerating] = useState(false);
  const [exporting, setExporting] = useState(false);

  const { collection, invalidateCollection, mapAll } = useCollection({
    property: core.properties.parent,
    value: resource.subject,
    filters: [
      {
        property: core.properties.isA,
        value: forms.classes.formInviteCode,
      },
    ],
  });

  // The publish slug makes a pretty link; before it's minted (form not yet
  // published / shared) the form's own subject works too — the server
  // resolves both.
  const shareBase = `${store.getServerUrl()}/form/${
    slug ?? encodeURIComponent(resource.subject)
  }`;

  const generate = () => {
    const parsed = Math.floor(Number(amount));

    if (!Number.isFinite(parsed) || parsed < 1) {
      toast.error('Enter how many invite links to create');

      return;
    }

    const clamped = Math.min(parsed, MAX_BATCH);
    setGenerating(true);

    createInviteCodes(store, resource.subject, clamped)
      .catch(() => toast.error('Could not create all invite links'))
      .then(() => invalidateCollection())
      .then(() => setGenerating(false));
  };

  const exportCodes = (fullLinks: boolean) => {
    setExporting(true);

    collectInviteCodes(store, resource.subject)
      .then(codes => {
        if (codes.length === 0) {
          toast.error('No invite links to export');

          return;
        }

        const lines = fullLinks
          ? codes.map(code => `${shareBase}?code=${encodeURIComponent(code)}`)
          : codes;

        downloadTextFile(
          lines.join('\n'),
          fullLinks ? 'invite-links.txt' : 'invite-codes.txt',
        );
      })
      .catch(() => toast.error('Could not export invite links'))
      .then(() => setExporting(false));
  };

  const exportItems: DropdownItem[] = [
    {
      label: 'Full links',
      id: 'export-full-links',
      disabled: exporting,
      onClick: () => exportCodes(true),
    },
    {
      label: 'Codes only',
      id: 'export-codes-only',
      disabled: exporting,
      onClick: () => exportCodes(false),
    },
  ];

  return (
    <Column gap="0.75rem">
      <Hint>
        Each invite link can be used for exactly one submission. Deleting a link
        revokes it.
      </Hint>
      <Card>
        <Column>
          <Row gap="0.5rem" center>
            <AmountInputWrapper>
              <InputStyled
                type="number"
                min={1}
                max={MAX_BATCH}
                value={amount}
                aria-label="Number of invite links"
                placeholder="Amount"
                onChange={e => setAmount(e.target.value)}
              />
              <Button
                onClick={generate}
                disabled={generating || !amount || Number(amount) < 1}
              >
                {generating ? 'Generating…' : 'Generate codes'}
              </Button>
            </AmountInputWrapper>
            {collection.totalMembers > 0 && (
              <DropdownMenu items={exportItems} Trigger={ExportTrigger} />
            )}
          </Row>
          {collection.totalMembers === 0 ? (
            <Hint>No invite links yet.</Hint>
          ) : (
            <Card.List maxHeight="20rem">
              {mapAll(({ index }) => (
                <InviteCodeRow
                  key={index}
                  collection={collection}
                  index={index}
                  shareBase={shareBase}
                />
              ))}
            </Card.List>
          )}
        </Column>
      </Card>
    </Column>
  );
}

interface InviteCodeRowProps {
  collection: Collection;
  index: number;
  shareBase: string;
}

function InviteCodeRow({
  collection,
  index,
  shareBase,
}: InviteCodeRowProps): JSX.Element | null {
  const invite = useMemberFromCollection(collection, index);
  const [code] = useString(invite, forms.properties.formCode);
  const [usedAt] = useNumber(invite, forms.properties.usedAt);

  if (!code) {
    return null;
  }

  const copyLink = () => {
    navigator.clipboard.writeText(
      `${shareBase}?code=${encodeURIComponent(code)}`,
    );
    toast.success('Invite link copied to clipboard');
  };

  const revoke = () => {
    invite.destroy();
  };

  return (
    <Row gap="0.5rem" center as="li">
      <CodeText
        data-testid="invite-code"
        data-used={usedAt !== undefined}
        $used={usedAt !== undefined}
      >
        {code}
      </CodeText>
      {usedAt !== undefined ? (
        <UsedBadge title={new Date(usedAt).toLocaleString()}>Used</UsedBadge>
      ) : (
        <IconButton title="Copy invite link" onClick={copyLink}>
          <FaLink />
        </IconButton>
      )}
      <IconButton
        title={usedAt !== undefined ? 'Delete' : 'Revoke'}
        onClick={revoke}
      >
        <FaTrash />
      </IconButton>
    </Row>
  );
}

const Hint = styled.p`
  margin: 0;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const AmountInputWrapper = styled(InputWrapper)`
  & button {
    border-start-start-radius: 0;
    border-end-start-radius: 0;
  }
`;

const CodeText = styled.span<{ $used: boolean }>`
  flex: 1;
  font-family: monospace;
  font-size: 0.9rem;
  color: ${p => (p.$used ? p.theme.colors.textLight : p.theme.colors.text)};
  text-decoration: ${p => (p.$used ? 'line-through' : 'none')};
`;

const UsedBadge = styled.span`
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: ${p => p.theme.colors.textLight};
`;
