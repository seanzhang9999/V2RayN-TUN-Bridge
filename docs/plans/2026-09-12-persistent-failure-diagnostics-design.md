# Persistent failure diagnostics

## Goal

Keep enough local evidence to diagnose a TUN failure after the user restores
connectivity or starts the application again. A new start must not erase the
only copy of the previous status or watchdog result.

## Design

The supervisor writes a bounded `mihomo-failure-history.json` file in the
existing protected runtime directory. Each entry contains the failure time,
checkpoint, redaction-safe error text, normalized core exit code and reason,
selected profile summary, and a small watchdog summary. It never contains the
generated proxy configuration, controller secret, subscription, UUID, or
password. The file keeps the most recent 20 entries using atomic replacement.

Before a new run starts, the launcher rotates the current status and supervisor
logs to `.previous` files. The supervisor similarly rotates the watchdog report
and core logs. One previous raw log set is sufficient because the bounded JSON
history preserves the long-term sequence while avoiding uncontrolled storage
growth and unnecessary retention of connection destinations.

The GUI reads only the latest persisted failure when it opens and adds one
clearly labelled line to the in-memory Runtime Log tab. Current status remains
authoritative: a historical failure must never make a healthy running instance
look failed.

## Verification

Tests cover bounded and corruption-tolerant history, failure recording, GUI
formatting, PowerShell diagnostic rotation, and version display. The complete
test suite and PowerShell parser must pass. Packaging uses a new versioned
directory and does not stop or overwrite the currently running TUN instance.
