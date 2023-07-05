
# Prefix Transport

**TLDR** - This transport allows up to prepend conjure connections with bytes that look like the
initialization of other protocols. This can help to circumvent blocking in some areas and better
understand censorship regimes, but is generally a short term solution.

The `Prefix_Min` transport is a strictly improved version of the existing `Min` transport and we
suggest migration.

## Description

This package implements the prefix transport for the conjure refraction-networking system. The
prefix transport operates in much the same way as the min transport, sending a tag in the fist
packet signalling to the station that the flow has knowledge of a secret shared with the station by
a previous registration.

TODO: Comparison to min transport

### Prefixes Supported by Default

TODO: The prefixes supported by default are as follows.

### Ports

TODO: Prefixes have default ports associated with them, but also allow port randomization.

### :warning: Sharp Edges :warning:

In general this transport will not properly mimic the protocols that are sent as a prefix and should
not be expected to do so.

## Integrating the Prefix Transport

Though the client dialer allows the use of TrasnportType  for compatibility reasons, the prefix
transport requires use of the newer Client Transport interface (`TransportConfig` in the dialer)
which is implemented by the `prefix.ClientTransport` object.

TODO: code change example.

## Adding a Prefix / Bidirectional Registration Prefix Overrides

In order to add a prefix ...

## :construction: Road-Map

These features are not necessarily planned or landing imminently, they are simply things that would
be nice to have.

- [ ] **Server Side Prefix Override From File** - file format shared between station and Reg server
  describing available prefixes outside of defaults.

- [ ] **TagEncodings** - Allow the tag to (by prefix configuration) be encoded using an encoder
  expected by the station, Base64 for example.

- [ ] **StreamEncodings** - Allow the Stream of client bytes to (by configuration) encoded /
  encrypted using a scheme expected by the station, AES or Base64 for example.

- [ ] **Randomization** - indicate segments of the prefix to be filled from a random source.

- [ ] **Prefix Revocation** - If there is a prefix that is known to be blocked and we don't want
  clients to use it, but we still want them to roll a random prefix, how do we do this?
