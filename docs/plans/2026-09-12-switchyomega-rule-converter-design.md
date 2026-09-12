# SwitchyOmega rule converter design

V2RayN TUN Bridge v0.1.7 adds a route helper in the existing GUI. Users paste
a SwitchyOmega Conditions list and receive v2rayN-compatible raw rule lines.
Positive conditions map to PROXY and conditions prefixed with `!` map to DIRECT.
The output is grouped with proxy rules first and direct rules second.

On explicit user action, Bridge saves a credential-free copy of the active route,
updates only the active RoutingItem ruleSet in one transaction, and restarts Bridge so the normal
v2rayN route reader loads it. Stable managed rule IDs allow later imports to replace
the previous Bridge groups without duplicates. Node profiles and credentials are
never modified. Parser, writer, backup, and replacement behavior are independently
tested.
