import { Link } from '@tanstack/react-router';
import { styled } from 'styled-components';
import { CARD_SUB_FONT } from '../cardSurface';
import { DriveAddress } from './DriveAddress';
import { UsageMeter } from './UsageMeter';
import { paths } from '../../routes/paths';
import type { NodeDriveUsage } from '../../helpers/managedServer';

/**
 * What Cloud Server holds for the drive in view, as the account portal shows
 * it: a usage bar and one line of size facts, then the drive's web address.
 * Whether it is in sync is the row's status line, not repeated here.
 *
 * Lives on the Cloud Server row rather than on the device card, which keeps to
 * what is true of the device (its status and how to disconnect it).
 */
export function CloudServerDetails({
  drive,
  usage,
  quotaBytes,
  signedIn,
}: {
  drive: string;
  usage: NodeDriveUsage | null;
  quotaBytes: number | null;
  /** Web addresses belong to the account, so they need a session. */
  signedIn: boolean;
}) {
  const used = usage ? usage.blobBytes + usage.loroBytes : null;

  return (
    <>
      {usage && used !== null && (
        <UsageMeter
          data-testid='cloud-server-usage'
          usedBytes={used}
          quotaBytes={quotaBytes}
          facts={[`${usage.resourceCount.toLocaleString()} resources`]}
          note={
            <StorageLink to={paths.storage} data-testid='storage-map-link'>
              See where space goes
            </StorageLink>
          }
        />
      )}
      {signedIn && <DriveAddress drive={drive} />}
    </>
  );
}

const StorageLink = styled(Link)`
  color: ${p => p.theme.colors.main};
  font-size: ${CARD_SUB_FONT};
`;
