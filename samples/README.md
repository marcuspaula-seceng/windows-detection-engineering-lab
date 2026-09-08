# Samples — provenance

The `.evtx` files are **not committed**. They are public, and reproducible from the data below.
Provenance and hashes are worth more in version control than the binaries.

## Source

```text
Repository  https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack
Licence     CC0-1.0 (public domain dedication)
Fetched     2026-09-07, via the GitHub API, 3 files out of 293
Executed    nothing -- EVTX is data, not a payload
```

## Files

| Local name | SHA-256 | Path in source repository |
|---|---|---|
| `T1059.001-powershell-payload.evtx` | `76DA739520ECFB51C0BC93A5856FF45C0CD5E038114826FEE30790F92FCE0FCA` | `TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload download via PowerShell.evtx` |
| `T1053.005-scheduled-task-creation.evtx` | `6F00C7423DA4CE91C6D3AA44DD81234CEF24340C74E3209F78B5CE9395F0D90A` | `TA0002-Execution/T1053.005-Scheduled Task/ID4688-4698 Persistent scheduled task with SYSTEM privileges creation.evtx` |
| `T1021.002-psexec-eternalromance.evtx` | `EF506D72D26CEC8B8A24BD0B726D530BD9EC793CF855FF3C2338CBCD31C0EFCA` | `EVTX_full_APT_attack_steps/ID4624,4688,5140,5145-Eternal Romance - MS17_010_psexec (GLOBAL).evtx` |

All three are 69,632 bytes with the `ElfFile` magic.

## Fetching

The `contents/` API returns 404 for these paths — they contain spaces and commas. The blob API
works:

```bash
R=mdecrevoisier/EVTX-to-MITRE-Attack

gh api "repos/$R/git/trees/HEAD?recursive=1" \
  --jq '.tree[] | select(.path|endswith(".evtx")) | .sha + "  " + .path'

gh api "repos/$R/git/blobs/<SHA>" --jq '.content' | base64 -d -i > samples/<name>.evtx
```

Verify against the SHA-256 above before use.

## What is in them

Telemetry from the dataset author's laboratory: the `OFFSEC` domain, hosts
`srvdefender01.offsec.lan` and `fs03vuln.offsec.lan`, account `admmig`. **No data from any
employer, client, or production environment appears anywhere in this repository.**

### Collection artefacts, not attack activity

In `T1021.002-psexec-eternalromance.evtx`, two groups of events belong to the researcher, not
to the intrusion:

- **`1102` — "the audit log was cleared"**, the first event in the file. In isolation this maps
  to `T1070.001`. In position, it is almost certainly the log being cleared to collect a clean
  sample.
- **File-share access to `Users\admmig\Desktop\MS17_010_psexec.evtx` over `C$`**, at the end of
  the capture. The file being read is the evidence file itself — this is the sample being
  collected.

Reading a dataset includes recognising the footprint of whoever collected it. Treating those
events as attack activity produces a report describing two intruders when there was one.

## Safety

```text
Nothing installed.        No third-party EVTX parser.
Nothing executed.         Get-WinEvent only reads the file.
Nothing imported.         These logs were never loaded into a system event log.
No sample URL was visited.
Host audit policy unchanged.
```

One practical note: extracting the **full** command line from the PsExec sample to a text file
was blocked by the host's antivirus. The payload string is detectable on its own, without
being executed. No exclusion was created and nothing was disabled — the tooling truncates long
fields instead (`-MaxFieldLength`, default 400).
