# Tun Interfaces

Conjure relies on local tunnel interfaces to transfer traffic from the detector
to the application. This allows the incorporation of IPtables rules for DNAT and
TCP session tracking managed by the kernel.

This package creates tun interfaces for go to write into and allocate if not
already created.

### Example Usage:

A  quick example can be seen below, though more complete examples are available
in the `examples` directory.

```go
    tun, err := tun.NewTun("tun2")
    if err != nil {
        fmt.Println("Failed to open tun - ", err)
        return
    }
    defer tun.Close()


    n, err := tun.Write(packet.Data())
    if err != nil {
        fmt.Println("Error writing into tun - ", err)
        break
    }
```

### Note

This module makes use of CGo interfaces and syscalls and as such will require
root.
