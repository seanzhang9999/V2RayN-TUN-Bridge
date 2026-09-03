# Source connection tabs

## Decision

Replace the unreliable application aggregation view with two switchable recent
connection tabs. One tab contains connections captured by TUN and the other
contains connections entering through the local mixed proxy on port 1081.

Each tab retains the existing connection columns and shows its ten newest
connections, including recently closed entries. Connections whose input source
cannot be identified are not guessed into either list; the monitor status shows
their count instead.

## Verification

- Unit-test independent ten-entry histories for TUN and mixed input sources.
- Run the complete test suite.
- Build the portable application and visually inspect both tabs at the default
  window size without starting TUN.
