type SharingStore = {
  isLocalOnlyDrive(drive: string): boolean;
  makeDriveLocal(drive: string): Promise<void>;
};

/** Resolve routing without interpreting a failed account lookup as no hosting. */
export async function prepareDriveSharing(
  store: SharingStore,
  drive: string,
  enrollments: { drive_subject: string; status: string }[],
): Promise<boolean> {
  if (store.isLocalOnlyDrive(drive)) return true;
  if (
    enrollments.some(e => e.drive_subject === drive && e.status !== 'Disabled')
  )
    return false;
  await store.makeDriveLocal(drive);

  return true;
}
