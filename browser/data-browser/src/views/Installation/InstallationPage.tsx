import { Button } from '@components/Button';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import { ContainerNarrow } from '@components/Containers';
import Markdown from '@components/datatypes/Markdown';
import { JSONEditor } from '@components/JSONEditor';
import { Column, Row } from '@components/Row';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import {
  core,
  publishZipRelease,
  readInstallationReview,
  server,
  updateInstallationRelease,
  useCanWrite,
  useSaveState,
  useStore,
  useString,
  useValue,
  type InstallationStatus,
  type JSONValue,
  type Server,
} from '@tomic/react';
import type { ResourcePageProps } from '@views/ResourcePage';
import type { JSONSchema7 } from 'ai';
import { constructOpenURL } from '@helpers/navigation';
import { useEffect, useId, useRef, useState } from 'react';
import {
  FaFloppyDisk,
  FaGear,
  FaPause,
  FaPlay,
  FaBan,
  FaTrash,
  FaArrowUp,
} from 'react-icons/fa6';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import {
  CapabilityList,
  capabilitiesFromPermissions,
} from '@chunks/Plugins/CapabilityList';
import { ConfigReference } from './ConfigReference';
import { AssignRights } from './AssignRights';
import { useInstallationConfigSchema } from './useInstallationConfigSchema';
import { ResourceInline } from '@views/ResourceInline/ResourceInline';
import { useCustomViews } from '@components/CustomViewProvider';
import {
  InstallationReviewDialog,
  type PendingInstallation,
} from '@chunks/Plugins/InstallationReviewDialog';

const UPDATE_VERB = {
  title: 'Update plugin',
  confirm: 'Update',
  busy: 'Updating…',
};

/**
 * One installed release on a drive, for either runtime. Status changes are
 * commits the server's Installation hook acts on: `active` installs,
 * `paused` unregisters it and keeps everything else, `revoked` or destroying
 * uninstalls. Uploading a newer zip repoints this same resource at the new
 * release, so the plugin keeps its config and the agent it signs as.
 */
export const InstallationPage: React.FC<
  ResourcePageProps<Server.Installation>
> = ({ resource }) => {
  const configLabelId = useId();
  const store = useStore();
  const canWrite = useCanWrite(resource);
  const navigate = useNavigateWithTransition();
  const { refresh: refreshCustomViews } = useCustomViews();
  const [confirm, setConfirm] = useState<'revoke' | 'uninstall'>();
  const [name] = useString(resource, core.properties.name);
  const [namespace] = useString(resource, server.properties.namespace);
  const [version] = useString(resource, server.properties.version);
  const [description] = useString(resource, core.properties.description);
  const [author] = useString(resource, server.properties.pluginAuthor);
  const [release] = useString(resource, server.properties.release);
  const [releaseId] = useString(resource, server.properties.releaseId);
  const [status, setStatus] = useValue(
    resource,
    server.properties.installationStatus,
  );
  const [grants] = useValue(resource, server.properties.grants);
  const [config, setConfig] = useValue(resource, server.properties.config);
  const [currentSchema] = useValue(resource, server.properties.jsonSchema);
  const schema = useInstallationConfigSchema(
    resource.subject,
    release,
    currentSchema as JSONSchema7 | undefined,
  );
  const [permissions] = useValue(resource, server.properties.pluginPermissions);
  const [pluginAgent] = useString(resource, server.properties.pluginAgent);
  const [configValid, setConfigValid] = useState(true);
  const [configSyntaxValid, setConfigSyntaxValid] = useState(true);
  const [configEdited, setConfigEdited] = useState(false);
  const saveState = useSaveState(resource);
  const [changing, setChanging] = useState(false);
  const [pending, setPending] = useState<PendingInstallation>();
  const [publishing, setPublishing] = useState(false);
  const zipInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Loro snapshots omit the server-computed manifest metadata, including
    // the config schema. Load it even when the installation is already cached.
    store
      .fetchResourceFromServer(resource.subject, { noWebSocket: true })
      .catch(error => toast.error(error.message));
  }, [store, resource.subject, release]);

  const title = `${namespace ? `${namespace}/` : ''}${name ?? ''}`;
  const currentStatus = (status as InstallationStatus | undefined) ?? 'draft';
  const declared = capabilitiesFromPermissions(permissions);
  const hasFullDriveAccess = declared.some(
    c => c.title === 'full-drive-access',
  );
  const grantNames = Array.isArray(grants)
    ? grants.map(String)
    : grants && typeof grants === 'object'
      ? Object.keys(grants)
      : [];

  const changeStatus = async (next: InstallationStatus) => {
    setChanging(true);

    try {
      await setStatus(next);
      await resource.save();
      await refreshCustomViews();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setChanging(false);
    }
  };

  /**
   * Publishes the uploaded zip as a release and reviews it. Nothing is
   * installed until the review is confirmed; the release itself is private
   * to this drive either way.
   */
  const handleZipChosen = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];

    if (!file) return;
    setPublishing(true);

    try {
      const drive = resource.get(core.properties.parent) as string;
      const {
        id,
        subject,
        release: published,
      } = await publishZipRelease(store, drive, file);
      setPending({
        review: readInstallationReview({ ...published, id }),
        release: { url: subject, id },
        currentConfig: config as JSONValue | undefined,
      });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setPublishing(false);
      if (zipInputRef.current) zipInputRef.current.value = '';
    }
  };

  const applyUpdate = async (
    p: PendingInstallation,
    nextConfig: JSONValue | undefined,
    nextGrants: string[],
  ) => {
    // The server compares these with the package, so a zip for a different
    // plugin is refused there. Saying so here is the clearer error.
    if (p.review.name !== name || p.review.namespace !== namespace) {
      throw new Error(
        `That package is ${p.review.namespace}/${p.review.name}, not ${title}. A plugin's name and namespace cannot change.`,
      );
    }

    await updateInstallationRelease(store, resource.subject, {
      release: p.release,
      grants: nextGrants,
      config: nextConfig,
      version: p.review.version,
    });
    await refreshCustomViews();
  };

  return (
    <ContainerNarrow>
      <Column gap='2rem'>
        <div>
          <Row justify='space-between' center>
            <Row center gap='1ch'>
              <PluginName>{title}</PluginName>
              <StatusBadge
                data-status={currentStatus}
                aria-label={`Status: ${currentStatus}`}
              >
                {currentStatus}
              </StatusBadge>
            </Row>
            {version && <span>v{version}</span>}
          </Row>
          {author && <PluginAuthor>by {author}</PluginAuthor>}
        </div>
        <Column>
          {canWrite && (
            <Row justify='flex-end' wrapItems>
              {currentStatus === 'active' && (
                <Button
                  subtle
                  disabled={changing}
                  onClick={() => changeStatus('paused')}
                >
                  <FaPause />
                  <span>Pause</span>
                </Button>
              )}
              {(currentStatus === 'paused' || currentStatus === 'draft') && (
                <Button
                  disabled={changing}
                  onClick={() => changeStatus('active')}
                >
                  <FaPlay />
                  <span>
                    {currentStatus === 'draft' ? 'Install' : 'Resume'}
                  </span>
                </Button>
              )}
              {currentStatus !== 'revoked' && (
                <label>
                  <Button as='div' subtle disabled={changing || publishing}>
                    <FaArrowUp aria-hidden />
                    <span>{publishing ? 'Publishing…' : 'Update'}</span>
                  </Button>
                  <input
                    ref={zipInputRef}
                    type='file'
                    style={{ display: 'none' }}
                    accept='application/zip'
                    disabled={changing || publishing}
                    onChange={handleZipChosen}
                  />
                </label>
              )}
              {currentStatus !== 'revoked' && (
                <Button
                  subtle
                  disabled={changing}
                  onClick={() => setConfirm('revoke')}
                >
                  <FaBan />
                  <span>Revoke</span>
                </Button>
              )}
              <Button
                alert
                disabled={changing}
                onClick={() => setConfirm('uninstall')}
              >
                <FaTrash />
                <span>Uninstall</span>
              </Button>
            </Row>
          )}
          {description && (
            <DescriptionWrapper aria-label='Plugin Description'>
              <Markdown text={description} />
            </DescriptionWrapper>
          )}
        </Column>
        <Column as='section' aria-label='Release'>
          <h3>Release</h3>
          {/* Two paragraphs, not a <br /> inside one message: a JSX element
              passed into a translated message lands in its fragment array
              without a key. */}
          <Identity>
            Pinned to <code>{releaseId}</code>
          </Identity>
          {release && release !== releaseId && (
            <Identity>
              from{' '}
              {/^https?:\/\//.test(release) ? (
                <a href={release} target='_blank' rel='noreferrer'>
                  {release}
                </a>
              ) : (
                release
              )}
            </Identity>
          )}
        </Column>
        <Column as='section' aria-label='Grants'>
          <h3>Grants</h3>
          {grantNames.length === 0 ? (
            <Muted>No capabilities were granted.</Muted>
          ) : (
            <Row wrapItems gap='0.4rem'>
              {grantNames.map(grant => (
                <Tag key={grant}>{grant}</Tag>
              ))}
            </Row>
          )}
        </Column>
        {pluginAgent && (
          <Column as='section' aria-label='Plugin agent'>
            <h3>Plugin agent</h3>
            <ResourceInline subject={pluginAgent} />
          </Column>
        )}
        {canWrite && pluginAgent && (
          <AssignRights installation={resource} disabled={hasFullDriveAccess} />
        )}
        <Column>
          <Row center justify='space-between'>
            <h3 id={configLabelId}>
              <Row gap='0.5ch' center>
                <FaGear />
                <span>Config</span>
              </Row>
            </h3>
            {canWrite && (
              <Button
                disabled={
                  !configValid ||
                  !configSyntaxValid ||
                  saveState.kind === 'saving' ||
                  saveState.kind === 'scheduled' ||
                  (!configEdited && saveState.kind !== 'dirty')
                }
                onClick={() => {
                  setConfigEdited(false);

                  return resource.save();
                }}
              >
                <FaFloppyDisk />
                <span>Save</span>
              </Button>
            )}
          </Row>
          <JSONEditor
            labelId={configLabelId}
            initialValue={JSON.stringify(config ?? {}, null, 2)}
            onChange={v => {
              try {
                setConfig(JSON.parse(v));
                setConfigEdited(true);
                setConfigSyntaxValid(true);
              } catch {
                setConfigSyntaxValid(false);
              }
            }}
            schema={schema as JSONSchema7 | undefined}
            showErrorStyling={!configValid}
            onValidationChange={setConfigValid}
          />
        </Column>
        {schema && <ConfigReference schema={schema as JSONSchema7} />}
        {declared.length > 0 && (
          <CapabilityList capabilities={declared} title='Permissions' />
        )}
      </Column>
      <InstallationReviewDialog
        pending={pending}
        onClose={() => setPending(undefined)}
        onInstall={applyUpdate}
        verb={UPDATE_VERB}
      />
      <ConfirmationDialog
        title='Revoke installation'
        show={confirm === 'revoke'}
        theme={ConfirmationDialogTheme.Alert}
        confirmLabel='Revoke'
        bindShow={open => !open && setConfirm(undefined)}
        onConfirm={() => changeStatus('revoked')}
        onCancel={() => setConfirm(undefined)}
      >
        Revoking uninstalls the plugin and retires its agent. The Installation
        record stays, so you can see what was installed; installing again needs
        a new Installation.
      </ConfirmationDialog>
      <ConfirmationDialog
        title='Uninstall plugin'
        show={confirm === 'uninstall'}
        theme={ConfirmationDialogTheme.Alert}
        confirmLabel='Uninstall'
        bindShow={open => !open && setConfirm(undefined)}
        onConfirm={async () => {
          const parent = resource.props.parent;
          await resource.destroy();
          await refreshCustomViews();
          navigate(constructOpenURL(parent));
        }}
        onCancel={() => setConfirm(undefined)}
      >
        Are you sure you want to uninstall this plugin? This removes the
        Installation record.
      </ConfirmationDialog>
    </ContainerNarrow>
  );
};

const PluginName = styled.span`
  font-weight: bold;
  font-size: 1.2rem;
`;

const PluginAuthor = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const StatusBadge = styled.span`
  font-size: 0.8rem;
  padding: 0.1rem 0.5rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
  color: ${p => p.theme.colors.textLight};
  text-transform: capitalize;

  &[data-status='active'] {
    color: ${p => p.theme.colors.main};
    border-color: ${p => p.theme.colors.main};
  }
`;

const DescriptionWrapper = styled.section`
  background-color: ${p => p.theme.colors.bg1};
  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};
  max-height: 33rem;
  overflow-y: auto;
`;

const Identity = styled.p`
  overflow-wrap: anywhere;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.textLight};
  margin: 0;
`;

const Muted = styled.p`
  color: ${p => p.theme.colors.textLight};
  margin: 0;
`;

const Tag = styled.span`
  border: 1px solid ${p => p.theme.colors.bg2};
  padding: 0.2rem 0.5rem;
  border-radius: ${p => p.theme.radius};
  font-size: 0.85rem;
`;
