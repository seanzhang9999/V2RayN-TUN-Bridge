# Restart and Connectivity Retest Design

## User actions

The main action row adds **Restart TUN**. It executes one elevated `Restart`
control action, waits for the existing supervisor to stop and release the TUN
adapter and mixed port, then starts a fresh supervisor using the currently
selected profile and latest v2rayN routing data. A failed stop prevents start.

The connectivity tab adds **Retest connectivity**. It repeats the same five
informational system, mixed-proxy, and Direct checks used after startup. Results
update the existing rows but never change the TUN process or its health state.

## Safety and verification

Both actions run outside the Tk event loop and disable all control buttons until
completion. Restart uses one elevation boundary and hidden PowerShell windows.
Tests cover command construction, preservation of profile options, the five
retest endpoints, and the use of port 1081 for mixed-proxy checks. The full test
suite and PowerShell parser must pass before v0.2.3 is packaged.
