# Conjure Registration API

The registration API is an HTTP API intended to support faster registrations for capable clients and potentially provide a registration mechanism for partners on behalf of their users. It hosts the HTTP API on a local port, and exposes a ZeroMQ socket where it publishes registrations on another port; these ports can be configured in `config.toml`.

## Setup

Set the `privkey_path` field in `config.toml` to the absolute path to the private key used for the station; this can be the same key as the one used for the detctor, although any Curve25519 key (32 bytes, or 64 if the public key is appended to the private key portion) will suffice. A list of accepted public keys should be set up in the `pubkeys` field; these are the public keys of each station you'd like to connect to the API. These are Z85-encoded, and thus should be 40 characters long. For easy retrieval of this encoding from clients' public keys, consider [z85](https://github.com/CarsonHoffman/z85).

Once those fields are set up, that's about all you need to do in the config unless you'd like to change the API or ZMQ ports. Set the `CJ_API_CONFIG` environment variable to the absolute path of `config.toml` when running it; using an `EnvironmentFile` in the systemd service definition is a great way to do this. Use an HTTP server (e.g. Caddy or Nginx) to terminate TLS connections and proxy requests to the local API (an example Caddyfile is included in this directory), and make sure that the chosen ZMQ port is open to the world.
