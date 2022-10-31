# Conjure Application



## Setup & Configuration

The only setup required for most stations is to set the path to the station's
private key in the `privkey_path` field of `config.toml`, and set the path to
the `config.toml` file using the `CJ_PROXY_CONFIG` environment variable. The
config already contains entries for two registration sources: the registration
API (with its public key), as well as the detector's IPC socket. The config also
contains basic parameters for heartbeating; you may consider lowering the
heartbeat interval if the proxy is missing many registrations. By default a
heartbeat is sent every 30 seconds, though if there is a regular message sent in
that interval it can serve as a heartbeat, meaning that the heartbeat procedure
has no potential for extra congestion.

## Registration Ingest (ZeroMQ Proxy)

This central functionality of the application is built around the ZMQ proxy
which combines multiple sources of registrations, such as the local detector and
the HTTP registration API, into one ZeroMQ socket for consumption. This means
that the application need only know about this proxy, and each registration
source need know nothing about its consumers; the proxy is the "stable" point of
the architecture.

### Registration sharing

if the `enable_share_over_api` setting is enabled and the `preshare_endpoint`
variable is set then the application will share decoy-registrations over the
API. This allows any station that may front very few decoys to benefit from the
decoy registrar along with other stations in the deployment.

## Transport Connections

The application is responsible for picking up, associating with registrations,
and transferring bytes for transport connections.

Currently the only supported Transports require TCP. When a new connection for a
registered phantom address the Detector forwards it through a TUN interface with
a DNAT rule so that the station can pick up the connection as though it was
originally destined for us. The DNAT also allows the application to respond to
the connection as a normal `conn` with the DNAT rule re-writing the source
address on the way out.

When a new connection is received over the TUN interface the application must
determine which registration the connection is associated with. This is done by
listening and reading into a buffer in a loop until a max number of bytes is
read or a timeout is reached without finding an associated registration.
Registrations have a fixed transport, and each transport may have a different
way of indicating the registration ID -- The null registrar prepends the random
32 byte session ID for example.

Once the registration is found the application opens a connection to the covert
address and bidirectionally tunnels traffic from the client to covert until one
side closes the connection.

See the [wiki page on
transports](https://github.com/refraction-networking/conjure/wiki/Transports)
for more information about specific transports

### Reconnection

Sessions are allowed to re-connect using a registration and transport for a
configurable period of time. This is useful when a connection is closed due to
network instability allowing for more rapid reconnection. It is not helpful to
connections killed by an inline censor.
