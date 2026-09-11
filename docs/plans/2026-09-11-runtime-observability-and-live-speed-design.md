# Runtime observability and live connection speed

## Goal

Replace misleading per-connection cumulative byte totals with sampled upload and
download rates, and make a single core exit produce one accurate GUI event
instead of a repeated generic crash message.

## Design

The existing Mihomo `/connections` stream remains the only traffic source. The
connection accumulator will retain the previous counters for each connection
and divide positive byte deltas by monotonic elapsed time. A newly observed
connection has no trustworthy prior sample, so its first rate is zero rather
than treating all bytes transferred since connection creation as one sample.
Closed connections remain in the ten-row recent list but their rate becomes
zero. The two connection tabs will label and render this value as instantaneous
upload/download speed; the existing proxy/direct aggregate speed uses the same
deltas.

The GUI will stop reopening and re-rendering an unchanged status file every 750
milliseconds. A small status-file watcher compares modification time, reads
only changed content, and emits each failure signature once. This removes both
the Windows file-contention window and the repeated error lines. Active states
whose recorded supervisor PID no longer exists are presented as stale rather
than current.

The supervisor will preserve the previous core log, record the actual process
return code, and classify exits using the watchdog report. Heartbeats will run
on a dedicated thread while the core is active, so slow route/DNS/PowerShell
checks cannot make the 20-second external watchdog kill a healthy core. The
watchdog remains useful when the entire supervisor process disappears. To
avoid treating Windows sleep/resume as a failure, it requires the heartbeat to
remain stale for an additional 30-second confirmation window before stopping
the core.

## Verification

Unit tests cover connection deltas, first samples, closed connections, status
deduplication, stale PID handling, and exit classification. Existing tests must
remain green. A new portable build is generated in a separate versioned dist
folder, so the currently running v0.1.2 process is not stopped or overwritten.
