
# Compatibility Packages

The station attempts to support older versions of the client. In order to ensure that the features
that have changed over the evolution of the client library this package and it's sub-packages
contain the original client side implementations for the station to test against.

These packages should NOT be used for real clients, or even included in non-test portions of the
regular Conjure library.

```tree
compatability
├── README.md
├── v0
│   └── compat.go
└── v1
    └── compat.go
```

**V0** compatibility requires support for the original buggy phantom selection algorithm

**V1** compatibility requires support for the updated, but still `math/rand` based varint phantom
selection algorithm
