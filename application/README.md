# Conjure ZeroMQ Proxy

This utility combines multiple sources of registrations, such as the local detector and the HTTP registration API, into one ZeroMQ socket for consumption by the application. This means that the application need only know about this proxy, and each registration source need know nothing about its consumers; the proxy is the "stable" point of the architecture.

## Setup

The only setup required for most stations is to set the path to the station's private key in the `privkey_path` field of `config.toml`, and set the path to the `config.toml` file using the `CJ_PROXY_CONFIG` environment variable. The config already contains entries for two registration sources: the registration API (with its public key), as well as the detector's IPC socket. The config also contains basic parameters for heartbeating; you may consider lowering the heartbeat interval if the proxy is missing many registrations. By default a heartbeat is sent every 30 seconds, though if there is a regular message sent in that interval it can serve as a heartbeat, meaning that the heartbeat procedure has no potential for extra congestion.
