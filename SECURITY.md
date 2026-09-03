# Security

## Data handling

- Profile credentials are read locally from the v2rayN database and are never
  uploaded by the application.
- Generated runtime configuration is written under a current-user-only folder
  in `%LOCALAPPDATA%` and removed during normal cleanup.
- Connection destinations and process names are held in memory only.
- The monitoring API listens on `127.0.0.1` and uses a new random secret on
  every run.
- Process cleanup checks the exact executable path, PID, start time, adapter,
  and listener instead of killing every process with a matching name.

## Reporting a vulnerability

Please use GitHub's private security advisory feature for this repository. Do
not include real subscriptions, UUIDs, passwords, server addresses, databases,
or unredacted runtime configuration in a public issue.

This project changes Windows routes and DNS handling. Test releases only on a
machine where you can restore normal network access manually.
