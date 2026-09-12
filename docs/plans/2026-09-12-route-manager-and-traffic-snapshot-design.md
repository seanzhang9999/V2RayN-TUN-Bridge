# Route manager and traffic snapshot design

V2RayN TUN Bridge v0.2.0 turns the one-way importer into a round-trip route
manager. It reads only the two Bridge-managed groups from v2rayN's active route
and shows Proxy and Direct entries separately. Both are editable and copyable. A
third editor accepts new SwitchyOmega conditions. Preview merges all inputs and
removes duplicates; replace uses the credential-free route backup and transactional
writer, then restarts Bridge.

The traffic snapshot is a separate tab. Start clears the previous capture and
accumulates every connection observed by the local Mihomo controller until Stop.
Rows are grouped by hostname, destination IP, inbound, route, and process, with
first/last times and unique connection counts. Data remains in GUI memory and is
only exported when the user copies a TSV summary.
