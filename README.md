# stealthInjector
Injects shellcode into remote processes using direct syscalls.

Direct syscalls will bypass a lot of AV/EDR detection techniques such as API userland hooking and monitoring.

The syscalls are retrieved dynamically through reading ntdll.dll instead of using hardcoded assembly. The advantage of retrieving the syscalls dynamically is that you don't have to worry about syscalls changing between Windows versions/patches, and you don't have to hardcode assembly which takes up space and time.

## Usage

```
Usage: stealthInjector.exe [-spawnProc | -pid <num>] [-unsafe]

-spawnProc: spawn nslookup.exe and inject into that
-pid <num>: inject into remote process given PID
-unsafe: inject shellcode using high-level API calls (likely to get caught by AV/EDR)
```
