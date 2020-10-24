# stealthInjector
Injects shellcode into remote processes using direct syscalls.

The syscalls are retrieved dynamically through reading ntdll.dll instead of using hardcoded assembly. The advantage of retrieving the syscalls dynamically is that you don't have to worry about syscalls changing between Windows versions/patches, and I don't have to hardcode assembly which takes up space and time.

## Usage

```
Usage: stealthInjector.exe [-spawnProc | -pid <num>] [-unsafe]

-spawnProc: spawn nslookup.exe and inject into that
-pid <num>: inject into remote process given PID
-unsafe: inject shellcode using high-level API calls (likely to get caught by AV/EDR)
```
