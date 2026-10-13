#!/usr/bin/env python3
"""Run synthetic restore acceptance against an existing scratch S3 bucket."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
if os.environ.get("ATOMIC_BLOB_BACKEND") != "s3":
    raise SystemExit("Set ATOMIC_BLOB_BACKEND=s3 and ATOMIC_S3_* for a scratch bucket")
output = Path(tempfile.mkdtemp(prefix="atomic-s3-restore-evidence-"))
print(f"Evidence: {output}", flush=True)
command = ["cargo", "run", "-p", "atomic-server", "--no-default-features",
           "--features", "light", "--example", "vault_restore_drill"]
for case in ("healthy", "missing", "corrupt"):
    env = dict(os.environ)
    env.pop("ATOMIC_RESTORE_DRILL_FAULT", None)
    if case != "healthy":
        env["ATOMIC_RESTORE_DRILL_FAULT"] = case
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=180)
    (output / f"{case}.stdout").write_text(result.stdout)
    (output / f"{case}.stderr").write_text(result.stderr)
    reports = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if len(reports) != 1:
        raise SystemExit(f"{case}: missing result; inspect {output}")
    report = reports[0]
    healthy = case == "healthy"
    assert (result.returncode == 0) == healthy, (case, result.returncode)
    assert report["complete"] == healthy, report
    assert report["attachment_matches"] == healthy, report
    assert report["resources_checked"] == 4, report
    assert report["restored_resource_editable"], report
    assert report["objects_unreadable"] == 0, report
    assert report["blob_backend"] == "s3", report
    print(f"{case}: passed (complete={report['complete']})", flush=True)
print("All three S3 restore checks passed. Synthetic fixture prefixes remain for inspection.")
