# SwitchyOmega rule converter design

V2RayN TUN Bridge v0.1.6 adds an offline helper in the existing GUI. Users paste
a SwitchyOmega Conditions list and receive v2rayN-compatible raw rule lines.
Positive conditions map to PROXY and conditions prefixed with `!` map to DIRECT.
The output is grouped with proxy rules first and direct rules second.

The helper never changes the v2rayN database or the established TUN runtime. Its
parser and formatter are independently tested, and packaging discovers the module
through the GUI's normal import path.
