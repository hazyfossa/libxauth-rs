# libxauth-rs

A rust re-implementation of libXau, the library for managing X server authority. 

## Security advisory

This is an educational project for me, it should be considered alpha software. Not ready for production use. While behaviour parity with original libXau is a goal, it is not guaranteed.

## Design

This library is intended to be used by display managers, as an alternative to calling the "xauth" utility.
It offers much better performance and removes the need to parse and write entries in an intermediate plaintext format.

The biggest performance win is in locking: the xauth cli creates a file lock on every invocation, while this library uses a single lock for all file operations and implements batching.

Choosing an appropriate authentication method for a client is out of scope, as this should be handled by your X binding, e.g. x11rb

## Planned features
- documentation
- stale lock removal
