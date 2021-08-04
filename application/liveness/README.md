# Conjure Liveness Module

The liveness module is designed to keep track of all the live hosts in the network by scanning the internet on a regular basis. The module provides cached liveness detection and uncached liveness detection. Cached liveness detection stores live hosts in previous scans to improve performance, while uncached liveness detection directly visits an IP address to check its liveness status. The validity of cached liveness detection is tested in a week-long survey of the internet where we measured the change of liveness across the network. We observed a downward trend in the similarity of discovered hosts.

## Usage

To start discovering the live hosts in the network, call `Periodic_scan(t string)` with goroutine, the argument indicates the interval of scanning and should be either "Minute" or "Hour". The function will scan the network.
To terminate the `Periodic_scan(t string)`, call `Stop()` which sends a stopping signal to terminate the function at the start of the next scanning cycle.
To check if an IP address is live in the network, call `PhantomIsLive(addr string, port uint16)` which return a bool and an error message if applicable.
