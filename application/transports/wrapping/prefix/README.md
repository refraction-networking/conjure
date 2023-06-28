
# Prefix Transport

This package implements the prefix transport for the conjure refraction-networking system. The
prefix transport operates in much the same way as the min transport, sending a tag in the fist
packet signalling to the station that the flow has knowledge of a secret shared with the station by
a previous registration.

TODO: Comparison to min transport

## Integrating the Prefix Transport

Though the client dialer allows the use of TrasnportType  for compatibility reasons, the prefix
transport requires use of the newer Client Transport interface (`TransportConfig` in the dialer)
which is implemented by the `prefix.ClientTransport` object.

TODO: code change example.

## Default Prefixes

The prefixes supported by default are as follows.

## Adding a Prefix / Bidirectional Registration Prefix Overrides

In order to add a prefix ...

## :warning: Sharp Edges :warning:

In general this transport will not properly mimic the protocols that are sent as a prefix and should
not be expected to do so.

---

- [X] AllowRegistrarOverrides -> DisableRegistrarOverrides
- [X] Prefix Override Randomize Default as Override system PoC test
- [X] Long Prefixes
- [X] flush after prefix test
- [X] BDAPI Fix test
- [ ] override test
- [ ] Prefix transport still works even if you send the wrong prefix
  - checks all prefixes (we could check after match if it was the right one)
