# atomic-loadtest

Load generator for atomic-server. One tokio task per virtual user, built on
`atomic_lib::client::ws::WsClient`, so the crypto and the wire format are the
real client's. It does not run a WASM client DB or presence heartbeats.

```
cargo build --profile e2e -p atomic-loadtest        # or --release
target/e2e/atomic-loadtest <scenario> --server http://localhost:9883 --out results.json
```

Every scenario prints a short summary and writes the full numbers as JSON.

## Starting a server for a run

Use an optimised build, never debug, and never run capacity numbers against an
in-process test server. The container has no IPv6, hence `ATOMIC_IP`.

```
mkdir -p /tmp/lt && rm -rf /tmp/lt/*
ATOMIC_IP=0.0.0.0 \
ATOMIC_WRITE_RATE_LIMIT=0 ATOMIC_ANONYMOUS_WRITE_RATE_LIMIT=0 \
target/e2e/atomic-server --initialize --port 9883 \
  --data-dir /tmp/lt/db --config-dir /tmp/lt/config &
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9883)" = 200 ]; do sleep 1; done
```

Gate on `curl` returning 200, not on the port (redb's lock outlives the socket).
Leave the limits at their defaults for a rate-limit scenario (N11). Raise
`ulimit -n` before thousands of clients; the tool reports `client_fd_limit`
failures when it is too low.

## Agents and drives

Virtual users are fresh ed25519 agents (`Agent::new`), never registered
anywhere: the server accepts AUTH from any key. Per run the tool creates a
"setup" agent and `K` drives over HTTP (`POST /commit`, genesis commit), each
readable by the public agent. For `commit`, the drive's write list holds the
setup agent plus every writer agent, so each writer signs its own commits and
the per-agent rate limit applies per writer. Subscribers are plain fresh agents
(public read). Drive creation counts against the anonymous/agent write limit.

## Scenarios

### connect

```
atomic-loadtest connect --clients 1000 --ramp-secs 60 --hold-secs 300 --drives 4
```

N clients connect, AUTH, SUB to a drive (round robin over `--drives`) and hold
with the real client's liveness rules (KEEPALIVE after 20 s of silence, close
after a 25 s unanswered probe). Reports connect and connect+auth latency
percentiles, failures by reason, clients that dropped while holding, keepalive
RTT.

### commit

```
atomic-loadtest commit --writers 50 --subscribers 500 --rate 1 --duration 60
```

One drive. Each writer creates its own resource (genesis commit) then edits it
`--rate` times per second over WS. Each subscriber holds a drive SUB. Reports:
COMMIT ack latency (send to COMMIT_OK), fan-out lag (commit sent to UPDATE
received, matched by commit id, falling back to subject), p50/p95/p99/max,
errors by code (429 etc.), achieved commits/s, and how many UPDATEs arrived
versus acked commits x subscribers. A rejected commit leaves that writer's
local chain ahead of the server, so later edits of that writer usually fail
too; with limits on, expect a cascade after the first 429.

By default the writer is open loop: it sends edit N+1 on schedule even if
edit N is not yet acked, so several commits for one subject can be in flight
on the socket. With `--closed-loop` each writer waits for COMMIT_OK (or an
error) of its previous commit before sending the next. It still targets
`--rate`; a tick that arrives while the previous commit is unacked is skipped
and counted as `skipped_ticks` (summary line and JSON). Achieved rate then
shows what the server sustains with one commit in flight per resource.

The tool advertises `commit-pace` in its `HELLO`. In `--closed-loop` mode a
writer also honours the server's load signals: it sends at most one commit per
`max(--debounce-ms, pace_ms)`, and on `BUSY` (error code 12) it waits the
told `retry_after_ms` plus jitter and resends the same commit (counted as
`busy_refusals`, not as an error). The summary and JSON report `server_pace_ms`
(distribution of the `pace_ms` that arrived on `COMMIT_OK`).

**Edits model.** `--edit-rate E` makes each writer edit locally `E` times per
second. Edits accumulate, and a writer sends one commit carrying every pending
edit whenever it may send (previous commit acked, pace and BUSY waits over).
It implies `--closed-loop`; `--rate` is ignored. This is how the real client
behaves, and it shows what pacing buys:

```
atomic-loadtest commit --writers 400 --subscribers 50 --edit-rate 2 --duration 60
```

Reports edits/s that reached the server (acked inside the window), commits/s,
edits per commit, `busy_refusals`, the `pace_ms` distribution and edit-to-server
latency (time from an edit to the ack of the commit that carried it). Edits
still pending when the window closes get 15 s to flush. After a BUSY the same
signed commit is resent unchanged (the writer's chain already moved past it),
so unlike the app it does not merge the edits made during the wait into it;
they ride in the next commit.

### storm

```
atomic-loadtest storm --clients 1000 --kill-cmd 'pkill -x atomic-server; sleep 1; ./start-server.sh' [--jitter]
atomic-loadtest storm --clients 1000 --expect-restart      # you restart the server by hand
```

Connects N clients, then drops them: with `--kill-cmd` the tool runs the
command (t0 = its start); with `--expect-restart` t0 is the first observed
socket close. Each client then reconnects with the real client's backoff (1 s,
doubling to 30 s, no jitter; `--jitter` is full jitter), re-AUTHs and re-SUBs.
Reports the time after t0 until 50/95/100 % of the clients are back, failed
attempts by reason, and who never came back within `--max-recover-secs`.
A drive created before the kill must survive the restart (same data dir).
