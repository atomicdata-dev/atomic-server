/** Repository-generated evidence for bundled providers, never publisher assertions. */
export function assessEvidence(report, id, bundleSha256, now = Date.now()) {
  if (
    !report ||
    report.schemaVersion !== 1 ||
    report.layer !== 'all' ||
    report.status !== 'passed'
  )
    return null;
  const timestamp = Date.parse(report.generatedAt);
  if (!Number.isFinite(timestamp) || timestamp > now + 300000) return null;
  if (!Array.isArray(report.integrations)) return null;
  const item = report.integrations.find(i => i?.id === id);
  if (
    !item ||
    typeof item.owner !== 'string' ||
    typeof item.version !== 'string' ||
    item.status !== 'passed' ||
    item.bundleSha256 !== bundleSha256 ||
    !Array.isArray(item.checks) ||
    !item.checks.length ||
    item.checks.some(
      c => !c || typeof c.name !== 'string' || c.status !== 'passed',
    )
  )
    return null;
  for (const check of ['reproducible-bundle', 'typecheck', 'fixtures'])
    if (!item.checks.some(c => c.name === check)) return null;
  if (
    !item.checks.some(
      c => typeof c.name === 'string' && c.name.startsWith('plugins::'),
    )
  )
    return null;
  return {
    owner: item.owner,
    version: item.version,
    testedAt: report.generatedAt,
    stale: now - timestamp > 30 * 86400000,
    checks: item.checks.length,
    live: 'not-run',
  };
}
