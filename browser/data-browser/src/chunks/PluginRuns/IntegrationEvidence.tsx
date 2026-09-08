import { useState } from 'react';
import type { Evidence } from '../../../../../integrations/tooling/evidence.mjs';

import type { BundledEvidenceId } from './integrationEvidenceLoader';

export function IntegrationEvidence({ id }: { id: BundledEvidenceId }) {
  const [evidence, setEvidence] = useState<Evidence | null>();
  const [loading, setLoading] = useState(false);

  const load = async () => {
    if (loading || evidence !== undefined) return;
    setLoading(true);

    try {
      const { loadEvidence } = await import('./integrationEvidenceLoader');
      setEvidence(await loadEvidence(id));
    } catch {
      setEvidence(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <details
      onToggle={event => {
        if (event.currentTarget.open) void load();
      }}
    >
      <summary>Repository test results</summary>
      <EvidenceContent evidence={evidence} />
    </details>
  );
}

function EvidenceContent({
  evidence,
}: {
  evidence: Evidence | null | undefined;
}) {
  if (evidence === undefined) return <p>Checking test evidence…</p>;
  if (evidence === null)
    return <p>No matching test evidence is available for this bundle.</p>;

  return (
    <div>
      <p>
        {evidence.owner} · {evidence.version}
      </p>
      <p>Offline checks passed: {evidence.checks}</p>
      <p>Tested on: {new Date(evidence.testedAt).toLocaleDateString()}</p>
      <EvidenceAge stale={evidence.stale} />
      <p>Live provider checks are not included in these results.</p>
    </div>
  );
}

function EvidenceAge({ stale }: { stale: boolean }) {
  if (!stale) return null;

  return <p>These results are over 30 days old.</p>;
}
