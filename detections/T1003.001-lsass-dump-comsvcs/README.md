# LSASS Memory Dump via comsvcs.dll MiniDump

| | |
|---|---|
| **ATT&CK** | [T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Tactic** | Credential Access |
| **Severity** | High |
| **Status** | Experimental (validated with sample events) |
| **Platforms** | Microsoft Defender XDR · Microsoft Sentinel · any SIEM via Sigma |

## Hypothesis

An attacker with local admin rights dumps the memory of `lsass.exe` to extract credentials
offline. To avoid dropping tools such as Mimikatz or ProcDump, they use a Windows-signed
binary already on the host: `rundll32.exe` loading `comsvcs.dll` and calling its `MiniDump`
export (a [LOLBAS](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/) technique).

## Detection logic

A process creation event where **all three** are true:

1. The process is `rundll32.exe`, by path **or** by its original file name (catches renamed copies).
2. The command line references `comsvcs`.
3. The command line calls the export by name (`MiniDump`, `MiniDumpW`) **or** by ordinal (`#24`, `#+24`).

Matching is case-insensitive.

## Files

| File | Purpose |
|---|---|
| `proc_creation_win_rundll32_comsvcs_minidump.yml` | Sigma rule (SIEM-agnostic source of truth) |
| `defender_xdr.kql` | Advanced Hunting query, ready to save as a Defender XDR custom detection |
| `sentinel_rule.yaml` | Microsoft Sentinel scheduled analytics rule (Azure-Sentinel repository format) |
| `tests/positive.json` | Events the rule **must** fire on |
| `tests/negative.json` | Events the rule **must not** fire on |

## Telemetry required

- **Microsoft Defender for Endpoint**: `DeviceProcessEvents`.
- **Sysmon**: Event ID 1 (process creation).
- **Windows Security log**: Event ID 4688 with command-line auditing enabled.

## Evasions covered

| Technique | Covered |
|---|---|
| Export called by name (`MiniDump` / `MiniDumpW`) | Yes |
| Export called by ordinal (`#24`, `#+24`) | Yes |
| Renamed `rundll32.exe` | Yes, via `OriginalFileName` |
| Mixed case in the command line | Yes |

## Known gaps

Being explicit about blind spots is part of the detection:

- **Renamed `comsvcs.dll`** (copied under another name): the `comsvcs` string is gone from the command line.
- **Heavy command-line obfuscation** (environment variables, caret insertion) can break string matching.
- **Other dumping tools** (ProcDump, custom tooling) are out of scope for this rule.

A complementary detection on **process access to `lsass.exe`** (Sysmon Event ID 10 /
Defender `OpenProcessApiCall`) would cover most of these gaps; it is planned as a separate detection.

## False positives and tuning

Very rare. Legitimate admins do not dump LSASS with `comsvcs.dll`. If an authorised red-team
or troubleshooting activity triggers it, add a filter on the specific host and account for
the duration of the exercise rather than weakening the logic.

## Triage guide

1. Check the parent process and the user: who launched `rundll32`, and from where?
2. Look for the dump file (`DeviceFileEvents`, `*.dmp`) and whether it left the host.
3. If not authorised: isolate the host and reset the credentials of every account logged on to it.

## Simulation

See [`simulation.md`](simulation.md).

## References

- MITRE ATT&CK: [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- LOLBAS: [comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/)
- Atomic Red Team: [T1003.001 tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)
