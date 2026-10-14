/** A recovered key and the epoch authenticated by its stored envelope. */
export type DriveKeyHandle = Readonly<{
  driveKey: Uint8Array;
  keyEpoch: number;
}>;

/** Validate at the adapter boundary, before storage or network work. */
export function validateDriveKey(key: DriveKeyHandle): void {
  if (
    !(key.driveKey instanceof Uint8Array) ||
    key.driveKey.length !== 32 ||
    !Number.isSafeInteger(key.keyEpoch) ||
    key.keyEpoch < 1 ||
    key.keyEpoch > 0xffffffff
  ) {
    throw new Error('Invalid Vault key or epoch');
  }
}

/** Expected confirmed history, independent of the surviving object listing. */
export type RecoveryExpectation = {
  lanes: Record<string, number>;
  checkpointN: number;
};

export function validateRecoveryExpectation(
  value: unknown,
): asserts value is RecoveryExpectation {
  if (!value || typeof value !== 'object')
    throw new Error('Invalid Vault recovery inventory');
  const { lanes, checkpointN } = value as RecoveryExpectation;

  if (
    !Number.isSafeInteger(checkpointN) ||
    checkpointN < 0 ||
    !lanes ||
    typeof lanes !== 'object' ||
    Array.isArray(lanes) ||
    Object.values(lanes).some(
      n => !Number.isSafeInteger(n) || n < 0 || n > 0xffffffff,
    )
  ) {
    throw new Error('Invalid Vault recovery inventory');
  }
}
