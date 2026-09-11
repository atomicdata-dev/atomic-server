# Full-instance backups

Run a dedicated replica with an output directory outside its data and config
folders. Data and config must be separate, non-overlapping directories; keep
`--cache-dir` outside both too:

```sh
atomic-server --data-dir /srv/atomic/data --config-dir /srv/atomic/config \
  --backup-dir /srv/atomic-backups
```

Request a backup on that same machine:

```sh
atomic-server --config-dir /srv/atomic/config backup --server http://127.0.0.1:9883
```

The command prints the archive path after verification, or exits nonzero on
failure. The server creates `backup.token` in its config directory with private
permissions. Backup control requires that token and a loopback connection; drive
write access does not grant instance backup access. Do not share the token.
The `--backup-dir` option also accepts `ATOMIC_BACKUP_DIR`.

The server drains admitted operations (up to 30 seconds), temporarily gates new
HTTP requests with `503` and `Retry-After`, and pauses incoming sync application.
It copies every redb table through one read transaction into a fresh database,
while a storage write transaction prevents all writers from crossing the capture
boundary. This includes Loro histories, retained signed envelopes, blobs, node
identity and internal metadata. Associated data/config files are captured under
the same barrier. Symlinks and special files fail the backup rather than escaping
the source directories. Operator edits to these directories should wait until the
capture finishes.

Capture time grows with database and file size; multi-GB pause duration has not
yet been benchmarked. Normal writes and queued sync resume before the staged
files are compressed.
Sync connections need not be disconnected: pending operations wait for admission
and then continue; a timed-out connection uses the existing reconnect/reconcile
path. No maintenance update is acknowledged and discarded. The output is a
ZIP64 archive named `atomic-backup-<UTC timestamp>-<process id>.zip`. File sizes
and BLAKE3 hashes, package version, Git revision, redb version, capture time, retention policy and source path
mapping are recorded in `manifest.json`. The ZIP is read back and hashes checked
before it receives its final name. Partial work uses private temporary paths.

This is a checkpoint of **this instance**, not proof that it received every
change from every peer. Replication freshness is explicitly reported as unknown.
It cannot recover Loro history or envelopes that were previously deleted or
never replicated. Cached vector indexes are outside the data/config roots and
are rebuilt when needed. External services, environment variables, separately
mounted storage and an exact executable are not bundled; retain your binary and
deployment configuration alongside the archive. A ZIP contains private data and
credentials; keep an independent protected copy off-machine.

## Restore

Use the same server version and a destination that does not exist:

```sh
atomic-server restore --archive /srv/atomic-backups/atomic-backup-EXAMPLE.zip \
  --target /srv/atomic-restored
```

Restore validates the manifest, paths, all file hashes and the redb database
before promoting staged files. It does not boot the node or start networking.
The result contains `data/`, `config/` and `manifest.json`. A marker in `data/`
prevents accidentally starting a normal server with copied node identities.
Inspect the restored files first. For actual recovery, stop the original instance
before explicitly activating the restored one:

```sh
atomic-server --data-dir /srv/atomic-restored/data \
  --config-dir /srv/atomic-restored/config --activate-restored
```

Reapply the original deployment settings, including the envelope-retention
policy recorded in the manifest. Activation can reconnect existing peers and
integrations. Reconnecting an old
checkpoint can merge newer remote changes back into it. Experimental branches
need a separate, network-isolated environment; the restore command deliberately
does not start one automatically. Do not activate both copies with the same node
identity on the same network.

## Nightly scheduling

`scripts/backup-instance.sh` accepts `ATOMIC_SERVER_BIN`, `ATOMIC_BACKUP_SERVER`
and the required `ATOMIC_BACKUP_TOKEN_FILE`. For example, a cron entry:

```cron
0 2 * * * ATOMIC_BACKUP_TOKEN_FILE=/srv/atomic/config/backup.token ATOMIC_SERVER_BIN=/usr/local/bin/atomic-server /path/to/atomic-server/scripts/backup-instance.sh >> /srv/atomic-backup.log 2>&1
```

On macOS, use the same script and environment with a launchd job whose
`StartCalendarInterval` has `Hour=2` and `Minute=0`, and set explicit
`StandardOutPath`/`StandardErrorPath`. The server rejects overlapping jobs. The
CLI waits for its job, detects server restarts or replaced status and exits
nonzero on failure. Check logs and disk capacity; nothing prunes old backups.

For status, use authenticated `GET /__atomic/backup` from loopback. An
unauthenticated request cannot see filesystem paths or backup errors. `POST` to
that route starts a job and returns its ID. Client disconnect does not cancel a
capture. Process crashes may leave `.atomic-backup-*` staging directories, but
never make a partial ZIP appear complete; remove stale staging only while no
backup job is running. Restore promotion errors may leave a partial destination;
inspect it and choose a fresh destination for retry.

Test a restore before relying on the first archive, then repeat periodically.
Take an extra checkpoint before risky experiments. Nightly retention accepts up
to a day of data loss; it does not retain every intermediate edit.
