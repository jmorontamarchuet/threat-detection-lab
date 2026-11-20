# Simulation – T1003.001 via comsvcs.dll

> Run this **only in an isolated lab VM** you own. Never on a corporate or client machine.

## Lab setup

- A disposable Windows 10/11 VM, snapshot taken before the test.
- Telemetry: [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with a
  configuration that logs Event ID 1 (process creation), or Windows Event 4688 with
  command-line auditing enabled.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) with `Invoke-AtomicRedTeam`.

## Steps

1. List the T1003.001 tests and pick the one that uses `comsvcs.dll`:
   ```powershell
   Invoke-AtomicTest T1003.001 -ShowDetailsBrief
   ```
2. Check its prerequisites, then run it:
   ```powershell
   Invoke-AtomicTest T1003.001 -TestNumbers <number> -GetPrereqs
   Invoke-AtomicTest T1003.001 -TestNumbers <number>
   ```
3. Clean up (removes the dump file):
   ```powershell
   Invoke-AtomicTest T1003.001 -TestNumbers <number> -Cleanup
   ```
4. Revert the VM to the snapshot.

Microsoft Defender may block the dump itself. That is fine: the **process creation is still
logged**, and that is the event this rule needs.

## Validating the rule against the lab logs

- **Sigma on the raw logs:** export the Sysmon log to `.evtx` and run the Sigma rule over it
  with [Chainsaw](https://github.com/WithSecureLabs/chainsaw) or
  [Zircolite](https://github.com/wagga40/Zircolite). The rule should report the test.
- **KQL without a paid tenant:** load the exported events into a free
  [Azure Data Explorer cluster](https://dataexplorer.azure.com/freecluster) and run the
  query logic from `defender_xdr.kql` against them.

## Result log

| Date | Environment | Fired | Notes |
|---|---|---|---|
| _pending_ | | | |
