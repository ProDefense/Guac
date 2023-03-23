# Guac

Guac is just an avocado in disguise.

## Quick Start
I'll make a Dockerfile later, but you need mingw and cargo nightly.
Set the `GUAC_PROC` as the process ID to inject shellcode into.

```
$ GUAC_PROC=1337 cargo build --release --target=x86_64-pc-windows-gnu
```

## How it works
Basic process injection with
1. `OpenProcess`
2. `VirtualAllocEx`
3. `WriteProcessMemory`
4. `CreateRemoteThread`
