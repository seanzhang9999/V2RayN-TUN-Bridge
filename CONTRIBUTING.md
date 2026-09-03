# Contributing

Bug reports and focused pull requests are welcome.

1. Reproduce the issue without including credentials or subscription data.
2. Run `python -m unittest discover -s tests -v` before submitting code.
3. Keep website checks informational; they must not decide whether TUN started.
4. Never add process-name-wide termination or expose the controller outside
   loopback.
5. Do not commit downloaded runtime binaries, generated configurations, logs,
   databases, or real endpoints.

For networking bugs, include Windows version, v2rayN version, selected protocol
and transport, physical interface type, the redacted application status, and
the smallest reproducible sequence.
