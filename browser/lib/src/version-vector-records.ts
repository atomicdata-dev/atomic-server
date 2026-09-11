/** serde-wasm-bindgen serializes Rust maps as JS Maps. Convert both levels
 * at the ClientDb boundary so all sync consumers receive the declared records. */
export function versionVectorRecords(
  value: unknown,
): Record<string, Record<string, number>> {
  const vectors = value instanceof Map ? Object.fromEntries(value) : value;

  return Object.fromEntries(
    Object.entries(vectors ?? {}).map(([subject, vector]) => [
      subject,
      vector instanceof Map ? Object.fromEntries(vector) : vector,
    ]),
  );
}
