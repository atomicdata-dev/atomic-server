import {
  core,
  forms,
  Resource,
  useNumber,
  useStore,
  useString,
} from '@tomic/react';
import { useEffect, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import QRCode from 'qrcode';
import {
  FaArrowUpRightFromSquare,
  FaCode,
  FaCopy,
  FaLink,
  FaShareNodes,
} from 'react-icons/fa6';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { Column, Row } from '@components/Row';
import { CodeBlock } from '@components/CodeBlock';

interface ShareLinkPanelProps {
  resource: Resource;
}

/**
 * Open form / copy link / QR code for a published form. The share slug is
 * normally minted lazily on a visitor's first `GET /form/:id/definition`
 * (`lib/src/forms.rs::mint_publish_slug`) — here we mint it eagerly right
 * after publish, so the owner doesn't have to wait for a visitor to hit the
 * form first. `resolve_form` accepts the form's own `did:ad:...` subject
 * directly, so that single fetch is enough to mint + persist the slug.
 */
export function ShareLinkPanel({
  resource,
}: ShareLinkPanelProps): JSX.Element | null {
  const store = useStore();
  const [dialogProps, show, , isOpen] = useDialog();
  const [publishedAt] = useNumber(resource, forms.properties.formPublishedAt);
  const [persistedSlug] = useString(resource, forms.properties.formPublishId);
  const [mintedSlug, setMintedSlug] = useState<string | undefined>();
  const mintingRef = useRef(false);

  const slug = persistedSlug || mintedSlug;
  const isPublished = publishedAt !== undefined;

  useEffect(() => {
    if (!isPublished || slug || mintingRef.current) {
      return;
    }

    mintingRef.current = true;
    let cancelled = false;
    let attempt = 0;

    // The `published-at` commit is applied to the local store optimistically
    // (`isPublished` flips immediately), but the server may not have
    // received/applied it yet — hitting `/definition` too early 410s ("not
    // published"). Retry with backoff instead of a single-shot attempt, so a
    // slow commit doesn't leave the share link stuck on "Preparing…" forever.
    // `mintingRef` stays true for the whole retry chain, not just one
    // attempt, so a re-render mid-retry can't start an overlapping chain.
    const tryMint = () => {
      fetch(
        `${store.getServerUrl()}/form/${encodeURIComponent(resource.subject)}/definition`,
      )
        .then(async res => {
          if (!res.ok) {
            throw new Error(`status ${res.status}`);
          }

          return res.json() as Promise<{ id?: string }>;
        })
        .then(data => {
          if (cancelled) return;

          if (data.id) {
            setMintedSlug(data.id);
          }

          mintingRef.current = false;
        })
        .catch(() => {
          if (cancelled) return;

          if (attempt < 5) {
            attempt += 1;
            setTimeout(tryMint, attempt * 1000);
          } else {
            mintingRef.current = false;
          }
        });
    };

    tryMint();

    return () => {
      cancelled = true;
      mintingRef.current = false;
    };
  }, [isPublished, slug, resource.subject, store]);

  if (!isPublished) {
    return null;
  }

  if (!slug) {
    return <DisabledTrigger title="Preparing share link…" />;
  }

  const shareUrl = `${store.getServerUrl()}/form/${slug}`;

  return (
    <>
      <Trigger type="button" title="Share form" onClick={show}>
        <FaShareNodes />
        Share
      </Trigger>
      <Dialog {...dialogProps} width="44rem">
        {isOpen && (
          <>
            <DialogTitle>
              <h1>Share form</h1>
            </DialogTitle>
            <DialogContent>
              <PanelContent shareUrl={shareUrl} resource={resource} />
            </DialogContent>
          </>
        )}
      </Dialog>
    </>
  );
}

function PanelContent({
  shareUrl,
  resource,
}: {
  shareUrl: string;
  resource: Resource;
}): JSX.Element {
  const [view, setView] = useState<'link' | 'embed'>('link');
  const [qrDataUrl, setQrDataUrl] = useState<string | undefined>();
  const [formName] = useString(resource, core.properties.name);

  useEffect(() => {
    let cancelled = false;

    QRCode.toDataURL(shareUrl, { margin: 1, width: 180 }).then(url => {
      if (!cancelled) setQrDataUrl(url);
    });

    return () => {
      cancelled = true;
    };
  }, [shareUrl]);

  const copyLink = () => {
    navigator.clipboard.writeText(shareUrl);
    toast.success('Link copied to clipboard');
  };

  return (
    <Inner gap="0.75rem">
      <ViewToggle role="tablist">
        <ViewButton
          type="button"
          role="tab"
          $active={view === 'link'}
          aria-selected={view === 'link'}
          onClick={() => setView('link')}
        >
          <FaLink /> Link
        </ViewButton>
        <ViewButton
          type="button"
          role="tab"
          $active={view === 'embed'}
          aria-selected={view === 'embed'}
          onClick={() => setView('embed')}
        >
          <FaCode /> Embed
        </ViewButton>
      </ViewToggle>
      {view === 'link' ? (
        <>
          {qrDataUrl && (
            <QrImage src={qrDataUrl} alt="QR code for the form link" />
          )}
          <LinkText title={shareUrl}>{shareUrl}</LinkText>
          <Row gap="0.5rem">
            <PanelButton type="button" onClick={copyLink}>
              <FaCopy /> Copy link
            </PanelButton>
            <PanelLink href={shareUrl} target="_blank" rel="noreferrer">
              <FaArrowUpRightFromSquare /> Open
            </PanelLink>
          </Row>
        </>
      ) : (
        <EmbedView shareUrl={shareUrl} formName={formName} />
      )}
    </Inner>
  );
}

function EmbedView({
  shareUrl,
  formName,
}: {
  shareUrl: string;
  formName: string | undefined;
}): JSX.Element {
  const snippet = buildEmbedSnippet(shareUrl, formName ?? 'Form');

  return (
    <EmbedInner>
      <EmbedHint>Paste this where you want the form to appear.</EmbedHint>
      <CodeBlock content={snippet} wordWrap />
    </EmbedInner>
  );
}

/** Iframe height starts at a reasonable default and is then driven by the
 * `atomic-form-resize` `postMessage` the published runtime posts
 * (`form-app/src/embedResize.ts`) — `event.source` (not the iframe's id) is
 * what actually disambiguates the message if a page embeds more than one
 * form; the id just makes the element easy to select. */
function buildEmbedSnippet(shareUrl: string, formName: string): string {
  const id = `atomic-form-${Math.random().toString(36).slice(2, 8)}`;
  const escapedName = formName.replace(/"/g, '&quot;');

  return `<iframe id="${id}" src="${shareUrl}?embed=1" width="100%" height="600" style="border:none;" title="${escapedName}"></iframe>
<script>
(function () {
  var iframe = document.getElementById('${id}');
  window.addEventListener('message', function (event) {
    if (
      event.data &&
      event.data.type === 'atomic-form-resize' &&
      event.source === iframe.contentWindow
    ) {
      iframe.style.height = event.data.height + 'px';
    }
  });
})();
</script>`;
}

const Trigger = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  height: 2rem;
  padding: 0 0.75rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  cursor: pointer;

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const DisabledTrigger = styled.button.attrs({ type: 'button', disabled: true })`
  display: inline-flex;
  align-items: center;
  height: 2rem;
  padding: 0 0.75rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.textLight};
  opacity: 0.6;
`;

const Inner = styled(Column)`
  padding: ${p => p.theme.size()};
  align-items: center;
  min-width: 14rem;
`;

const ViewToggle = styled.div`
  display: flex;
  gap: 0.25rem;
  width: 100%;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
`;

const ViewButton = styled.button<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  height: 1.85rem;
  padding: 0 0.6rem;
  border: none;
  border-bottom: 2px solid
    ${p => (p.$active ? p.theme.colors.main : 'transparent')};
  background: none;
  color: ${p => (p.$active ? p.theme.colors.text : p.theme.colors.textLight)};
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};
  cursor: pointer;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const EmbedInner = styled(Column)`
  gap: 0.5rem;
  width: 22rem;
  max-width: 100%;
`;

const EmbedHint = styled.span`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const QrImage = styled.img`
  width: 10rem;
  height: 10rem;
  border-radius: ${p => p.theme.radius};
`;

const LinkText = styled.span`
  max-width: 14rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const PanelButton = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  height: 1.85rem;
  padding: 0 0.6rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.text};
  cursor: pointer;

  &:hover {
    background-color: ${p => p.theme.colors.bg2};
  }
`;

const PanelLink = styled.a`
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  height: 1.85rem;
  padding: 0 0.6rem;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.text};
  text-decoration: none;

  &:hover {
    background-color: ${p => p.theme.colors.bg2};
  }
`;
