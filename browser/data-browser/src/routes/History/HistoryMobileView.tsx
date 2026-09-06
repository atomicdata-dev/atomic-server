import { useMemo } from 'react';
import type { HistoryViewProps } from './HistoryViewProps';
import { styled } from 'styled-components';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Column } from '../../components/Row';
import { VersionTitle } from './VersionTitle';
import { VersionScroller } from './VersionScroller';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../components/Dialog';
import type { Version } from '@tomic/react';
import { useStore, Resource, type AtomicValue } from '@tomic/react';
import {
  ResourceDiff,
  useResourceDiff,
} from '@components/ResourceDiff/ResourceDiff';
import { plural } from '@helpers/plural';
import { Tabs } from '@components/Tabs';
import { ResourceCardDefault } from '@views/Card/ResourceCard';

export function HistoryMobileView({
  resource,
  groupedVersions,
  selectedVersion,
  olderVersion,
  isCurrentVersion,
  onSelectVersion,
  onVersionAccept,
  attribution,
}: HistoryViewProps) {
  const [dialogProps, showDialog, closeDialog] = useDialog();
  const store = useStore();

  const selectedVersionResource = useMemo(() => {
    const res = new Resource(resource.subject);
    res.setStore(store);
    res.applyHydratedValues(
      selectedVersion.propvals.entries() as Iterable<[string, AtomicValue]>,
    );

    return res;
  }, [store, resource.subject, selectedVersion]);

  const olderVersionResource = useMemo(() => {
    if (!olderVersion) return undefined;
    const res = new Resource(resource.subject);
    res.setStore(store);
    res.applyHydratedValues(
      olderVersion.propvals.entries() as Iterable<[string, AtomicValue]>,
    );

    return res;
  }, [store, resource.subject, olderVersion]);

  const diff = useResourceDiff(olderVersionResource, selectedVersionResource);

  const changesCountText = plural(diff.changedProps.length, [
    '1 Change',
    '# Changes',
  ]);

  const tabs = [
    { label: changesCountText, value: 'changes' },
    { label: 'Resource', value: 'resource' },
  ];

  const handleVersionSelect = (version: Version) => {
    onSelectVersion(version);
    showDialog();
  };

  return (
    <>
      <CenteredScroller
        title={`History of ${resource.title}`}
        subject={resource.subject}
        groupedVersions={groupedVersions}
        selectedVersion={selectedVersion}
        onSelectVersion={handleVersionSelect}
      />
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Version</h1>
        </DialogTitle>
        <DialogContent>
          <Column fullHeight>
            {selectedVersion && (
              <>
                <VersionTitle
                  version={selectedVersion}
                  attribution={attribution}
                />
                <StyledCard>
                  <Tabs tabs={tabs} label='History'>
                    <Card.Content>
                      <Tabs.Panel value='changes'>
                        <ResourceDiff diff={diff} />
                      </Tabs.Panel>
                      <Tabs.Panel value='resource'>
                        <ResourceCardDefault
                          resource={selectedVersionResource}
                        />
                      </Tabs.Panel>
                    </Card.Content>
                  </Tabs>
                </StyledCard>
              </>
            )}
          </Column>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => closeDialog(false)} subtle>
            Cancel
          </Button>
          <Button onClick={onVersionAccept} disabled={isCurrentVersion}>
            Restore this version
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

const StyledCard = styled(Card)`
  overflow: auto;
`;

const CenteredScroller = styled(VersionScroller)`
  margin-inline: auto;
`;
