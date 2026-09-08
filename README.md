# windows-detection-engineering-lab

Sigma detection rules for Windows, validated against publicly licensed EVTX samples and
against declared test fixtures, in CI.

[![validate-detections](https://github.com/marcuspaula-seceng/windows-detection-engineering-lab/actions/workflows/validate.yml/badge.svg)](https://github.com/marcuspaula-seceng/windows-detection-engineering-lab/actions/workflows/validate.yml)

---

## What this is

A detection-engineering lab built around one idea:

> **A detection rule defines both what it catches and what it lets through.
> Only the first half usually gets written down.**

Every rule here ships with the evidence it was built from, the fixtures that exercise it, and
an explicit statement of what it does *not* detect.

## What this is not

```text
Not production detections.       Not tuned against any organisation's baseline.
Not an incident response record. No real telemetry from any employer or client.
Not vendor-converted.            Rules have not been run through a real SIEM backend.
```

---

## Contents

```text
sigma/     detection rules, written from scratch
tools/     a small Sigma evaluator and an EVTX field-mapper (no pySigma required)
tests/     fixtures with the expected verdict declared per case
samples/   provenance and fetch instructions for the public EVTX used (files not committed)
docs/      licensing analysis
```

---

## The rule

`sigma/marcus_schtasks_system_persistence.yml` — a scheduled task created via `schtasks.exe`
that runs as **SYSTEM** with a **high-frequency or boot trigger**.

Each element on its own is legitimate. Administrators create scheduled tasks; installers run
them as SYSTEM; monitoring runs frequently. The combination — maximum privilege plus
persistent re-execution — is narrow.

The community already covers the base case (`SigmaHQ` has a `schtasks /create` rule at
`level: low`, because it fires for every installer). This rule adds specificity so the level
can honestly be higher, without becoming noise.

```yaml
selection_tool:              Image|endswith '\schtasks.exe'  AND  CommandLine contains all
                             of ' /create ' and ' /ru '
selection_system_account:    ' /ru SYSTEM'  or  ' /ru "NT AUTHORITY\SYSTEM"'  or ...
selection_frequent_trigger:  ' /sc minute'  or  ' /sc onstart'  or  ' /sc onlogon'
filter_installer_parent:     ParentImage starts with 'C:\Program Files'
condition:                   all of selection_* and not filter_installer_parent
level:                       medium
status:                      experimental
```

`status: experimental` and `level: medium` are deliberate. It has been validated against one
real event and eight fixtures — that does not justify `stable`, and it does not justify `high`
in an environment where configuration management legitimately creates SYSTEM tasks.

---

## Validation

### Against real data

Public EVTX samples (CC0) are normalised from Event ID 4688 into the Sigma
`process_creation` taxonomy and evaluated:

```text
8 real process-creation events from 3 public samples

  1 match      schtasks.exe /create /sc minute /mo 1 /tn eviltask
                             /tr C:\tools\shell.cmd /ru SYSTEM
  7 no-match   cmd.exe, powershell.exe, conhost.exe, cscript.exe

  0 false positives
```

The most useful negative is `cscript.exe` running a `.vbs` silently as SYSTEM — an event that
looks malicious at a glance and is in fact the Microsoft Monitoring Agent doing its job. The
rule does not fire on it.

### Against fixtures

Eight cases, each declaring its expected verdict, run in CI:

| Case | Expected | What it proves |
|---|---|---|
| Copy of the real event | MATCH | base case |
| `/ru "NT AUTHORITY\SYSTEM"` + `/sc onstart` | MATCH | syntax variants |
| SYSTEM but `/sc weekly` | NO MATCH | the trigger condition is load-bearing |
| `/sc minute` but user account | NO MATCH | the privilege condition is load-bearing |
| Installer parent in `Program Files` | NO MATCH | the filter branch works |
| Same as base, `ParentImage` absent | MATCH | the filter does not shield an attacker |
| All uppercase | MATCH | case-insensitivity **demonstrated, not assumed** |
| `Register-ScheduledTask` via API | NO MATCH | **known false negative** |

### Known false negative

`Register-ScheduledTask` (or the Task Scheduler COM API) creates the same task **without ever
launching `schtasks.exe`**. No `process_creation` rule detects that. Covering it requires a
second rule against Event ID `4698`, which is not written here — and therefore not claimed.

---

## Reproducing the results

```bash
pip install -r requirements.txt
python tools/run_tests.py            # fixtures — this is what CI runs
```

Against the real samples, on Windows:

```powershell
# see samples/README.md for provenance, hashes and how to fetch them
.\tools\Export-EvtxToJson.ps1 -Path .\samples -OutFile .\tools\events-normalized.json
python tools\sigma_eval.py sigma\marcus_schtasks_system_persistence.yml tools\events-normalized.json
```

`Export-EvtxToJson.ps1` uses only `Get-WinEvent`, which ships with Windows. Nothing is
installed, nothing is imported into the system event log, and no audit policy is changed.

---

## Design notes

**`tools/sigma_eval.py` is a deliberate subset, not a pySigma replacement.** It supports
`contains`, `contains|all`, `startswith`, `endswith`, exact match, list-as-OR, and the
`all of x_*` / `1 of x_*` condition forms. It **refuses a rule** that uses anything else,
rather than silently returning a wrong verdict. A validator that quietly ignores what it does
not understand is worse than no validator — it issues a false pass.

**The field mapping is where the bugs live.** In EVTX 4688, `ProcessId` is the *creating*
process, not the created one. It maps to Sigma's `ParentProcessId`. Mapping it to `ProcessId`
inverts the whole process tree and nothing warns you.

**The same Event ID does not mean the same fields.** Across the three public samples used here,
4688 appears with 15 fields on one host and 9 on another — the older schema has no
`ParentProcessName` at all. A rule written against `ParentImage` silently fails to fire on
those hosts. That is measured, not assumed: 5 of the 8 events have no parent field.

---

## Limitations

- Eight real events. That is not a fleet, and it cannot establish a real false-positive rate.
- No organisational baseline. How noisy this rule is depends entirely on how much SYSTEM
  automation an environment runs.
- Not converted with `sigma-cli` and not executed on a real SIEM backend. The evaluator here
  is mine, and a tool agreeing with itself is not independent validation.
- Validated against Event ID 4688 only — not against Sysmon.
- The sample telemetry comes from the dataset author's lab (`OFFSEC` domain). Some events in
  it are collection artefacts rather than attack activity; `samples/README.md` says which.

---

## Licence

**Not yet chosen.** See `docs/LICENSING.md`. Until a licence file exists, default copyright
applies and no reuse rights are granted.

---

## Author

Marcus Paula — Security & Infrastructure Engineer · Dublin, Ireland
