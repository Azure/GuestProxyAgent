# Analyze Windows Heap Growth with UMDH

This guide uses the User-Mode Dump Heap (UMDH) tool and the user-mode stack
trace database (UST) to identify allocation call stacks whose live heap usage
grows over time in `GuestProxyAgent.exe`.

UMDH tracks allocations made through the Windows heap manager. It does not
explain direct `VirtualAlloc` growth, thread-stack commit, or mapped-file growth.
Use WPA/WPR or VMMap for those categories.

## 1. Install current Debugging Tools for Windows

Download and run the latest Windows SDK installer:

<https://developer.microsoft.com/windows/downloads/windows-sdk/>

Select **Debugging Tools for Windows**. Use a debugger build matching or newer
than the target OS. For Windows build 26100, SDK build 26100 or newer is
appropriate.

Open an elevated PowerShell session and define the x64 tool directory:

```powershell
$debuggers = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
```

Verify that UMDH, GFlags, and CDB come from the same current SDK installation:

```powershell
"umdh.exe", "gflags.exe", "cdb.exe" | ForEach-Object {
    (Get-Item "$debuggers\$_").VersionInfo |
        Select-Object FileName, FileVersion
}
```

Do not accidentally invoke an older copy from another directory or from
`PATH`. SDK build `10.0.28000.2705`, for example, is suitable for Windows build
26100.

## 2. Enable UST and configure its capacity

Enable allocation stack collection for future instances of the executable:

```powershell
& "$debuggers\gflags.exe" /i GuestProxyAgent.exe +ust
& "$debuggers\gflags.exe" /i GuestProxyAgent.exe /tracedb 1024
```

The trace database consumes diagnostic memory as it grows. Start with 256 MB
for a low-allocation process. Use 1024 MB when UMDH reports that the database
is full.

Verify the registry configuration:

```powershell
& "$debuggers\gflags.exe" /i GuestProxyAgent.exe

Get-ItemProperty `
  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GuestProxyAgent.exe" |
  Select-Object GlobalFlag, StackTraceDatabaseSizeInMb
```

The expected UST flag is:

```text
GlobalFlag = 0x00001000
```

Do not enable PageHeap. UMDH only requires `+ust`.

## 3. Fully restart GuestProxyAgent

Image-file GFlags apply only when a process starts. Updating GFlags does not
change an already-running process.

Discover the service from the current process, stop it completely, and start a
new instance:

```powershell
$oldProcess = Get-Process GuestProxyAgent
$service = Get-CimInstance Win32_Service |
    Where-Object ProcessId -eq $oldProcess.Id

Stop-Service $service.Name
Wait-Process -Id $oldProcess.Id
Start-Service $service.Name

$process = Get-Process GuestProxyAgent
$process | Select-Object Id, StartTime, Path
```

Confirm that the PID changed. Reassign `$process` after every service restart.

## 4. Verify UST inside the running process

Registry configuration describes future processes. Verify the flag in the
actual running process:

```powershell
& "$debuggers\cdb.exe" -p $process.Id -c "!gflag; qd"
```

Expected output includes:

```text
Current NtGlobalFlag contents: 0x00001000
ust - Create user mode stack trace database
```

The `qd` command detaches CDB without terminating GuestProxyAgent.

## 5. Configure symbols

UMDH resolves allocation stacks through `_NT_SYMBOL_PATH`. The private PDB must
exactly match the running `GuestProxyAgent.exe` binary.

```powershell
$env:_NT_SYMBOL_PATH = "C:\Temp\GPA\2026.09.15.01;srv*C:\Temp\GPA\symbols*https://msdl.microsoft.com/download/symbols"
```

Replace the first directory with the location of the matching
`azure_proxy_agent.pdb`.

## 6. Verify UMDH collection

Take a disposable snapshot to confirm that UST contains real stack IDs:

```powershell
& "$debuggers\umdh.exe" `
    -p:$($process.Id) `
    -f:C:\Temp\GPA\umdh-test.txt
```

Verify that the file contains IDs other than `BackTrace0`:

```powershell
Select-String C:\Temp\GPA\umdh-test.txt `
    -Pattern 'BackTrace(?!0\b)[0-9A-F]+' |
    Select-Object -First 5
```

Valid output contains identifiers such as `BackTraceF719C4C2`. `BackTrace0`
means that no allocation stack was recorded for that allocation.

If UMDH reports that the stack trace database is full:

1. Confirm that current x64 SDK tools are being used.
2. Set `/tracedb 1024`.
3. Fully stop and start the service.
4. Reassign `$process` to the new PID.
5. Verify `!gflag` again and repeat the test snapshot.

Do not use a snapshot containing only `BackTrace0` as a baseline.

## 7. Choose a stable baseline

The verification snapshot does not need to be the analysis baseline. Allow
startup allocations to settle first. Capture the baseline during representative
normal operation, after any expected initialization activity has completed.

```powershell
$baselinePid = (Get-Process GuestProxyAgent).Id

& "$debuggers\umdh.exe" `
    -p:$baselinePid `
    -f:C:\Temp\GPA\umdh-before.txt
```

For periodic cache cleanup, choose snapshot timing based on the question:

- Capture immediately before and after a cleanup to identify memory released by
  that cleanup.
- Capture immediately after two consecutive cleanups to determine whether the
  post-cleanup memory floor is increasing.
- Capture during equivalent normal workloads to avoid treating expected active
  connections or queued work as leaks.

## 8. Capture after heap growth

After several hours of representative workload, verify that GuestProxyAgent has
not restarted:

```powershell
$currentProcess = Get-Process GuestProxyAgent

if ($currentProcess.Id -ne $baselinePid) {
    throw "GuestProxyAgent restarted; these snapshots cannot be compared"
}
```

Capture the second snapshot from the same PID:

```powershell
& "$debuggers\umdh.exe" `
    -p:$baselinePid `
    -f:C:\Temp\GPA\umdh-after.txt
```

## 9. Generate and inspect the diff

Compare the snapshots. The first file is the older snapshot and the second is
the newer snapshot:

```powershell
& "$debuggers\umdh.exe" -d `
    C:\Temp\GPA\umdh-before.txt `
    C:\Temp\GPA\umdh-after.txt |
    Set-Content C:\Temp\GPA\umdh-diff.txt
```

Display the first positive entries:

```powershell
Select-String C:\Temp\GPA\umdh-diff.txt -Pattern '^\+\s' |
    Select-Object -First 30
```

A growth entry has this general form:

```text
+ BYTES_DELTA (NEW_BYTES - OLD_BYTES) NEW_COUNT allocs BackTrace...
+ COUNT_DELTA (NEW_COUNT - OLD_COUNT) BackTrace... allocations
```

Prioritize stacks with:

- Large positive byte growth.
- Increasing allocation counts.
- Growth repeated across multiple comparable intervals.
- The last symbolized GuestProxyAgent or dependency frame above the allocator.

A positive delta means those allocations were live in the later snapshot. It
does not by itself prove a leak: active connections, bounded caches, and
one-time lazy initialization can also produce positive deltas. Repeated diffs
under equivalent conditions establish whether growth is persistent.

## 10. Correlate stacks with source

Private symbols should produce frames resembling:

```text
GuestProxyAgent!proxy_agent_shared::...
GuestProxyAgent!azure_proxy_agent::...
GuestProxyAgent!regex_automata::...
```

The first application frame above `RtlAllocateHeap`, Rust allocation routines,
or a Windows allocation API usually identifies the owning code path.

Windows APIs may require caller-managed cleanup even when allocation occurs in
a system DLL. Examples include:

- `NetUserGetLocalGroups` buffers released with `NetApiBufferFree`.
- `LsaGetLogonSessionData` buffers released with `LsaFreeReturnBuffer`.

## 11. Disable diagnostics afterward

UST settings persist until explicitly removed. Disable them and restore the
default trace database size:

```powershell
& "$debuggers\gflags.exe" /i GuestProxyAgent.exe -ust
& "$debuggers\gflags.exe" /i GuestProxyAgent.exe /tracedb 0
```

Restart the service so that the diagnostic overhead is removed from the running
process:

```powershell
Stop-Service $service.Name
Wait-Process -Id (Get-Process GuestProxyAgent).Id
Start-Service $service.Name
```

## Limitations and cautions

- UST increases CPU usage and Private Bytes. Compare snapshots from the same
  UST-enabled process, not UST measurements against normal production runs.
- UMDH reports live Windows heap allocations, not total process Private Bytes.
- Direct `VirtualAlloc`, mapped files, and stack commit require VMMap or WPR/WPA.
- A matching PDB improves attribution but does not affect whether UST records an
  allocation.
- UMDH logs can contain process addresses and internal symbols. Treat them as
  diagnostic artifacts and review them before sharing outside the engineering
  team.
