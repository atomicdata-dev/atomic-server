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
  managed,
  managedBy,
}: {
  drive: string;
  usage: NodeDriveUsage | null;
  quotaBytes: number | null;
  /** Web addresses belong to the account, so they need a session. */
  signedIn: boolean;
  /** This account pays for the drive's plan. Everyone else just sees it. */
  managed: boolean;
  /** Name the paying account chose to show members, when the node sent one. */
  managedBy?: string;
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
      {managed ? (
        signedIn && <DriveAddress drive={drive} />
      ) : (
        <Managed data-testid='cloud-server-managed-elsewhere'>
          {managedBy
            ? `This drive is on Cloud Server (managed by ${managedBy}). Only that account can change the plan or the web address.`
            : 'This drive is on Cloud Server (managed by another account). Only that account can change the plan or the web address.'}
        </Managed>
      )}
    </>
  );
}

const Managed = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const StorageLink = styled(Link)`
  color: ${p => p.theme.colors.main};
  font-size: ${CARD_SUB_FONT};
`;
