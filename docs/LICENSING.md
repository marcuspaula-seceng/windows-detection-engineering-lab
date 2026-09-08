# Licensing analysis

**Status: NO LICENCE CHOSEN. This is a human decision and has not been made.**

Until a `LICENSE` file exists, default copyright applies: the work is Marcus Paula's, and no
reuse rights are granted to anyone. Publishing without a licence is a valid choice — it is not
an oversight.

---

## 1. Origin — why this repository is clean

```text
Created            2026-09-07, from scratch
Employer material  NONE
Client material    NONE
Prior-employment
  derived code     NONE
Third-party code   NONE
```

Everything here was written for this repository. No Sigma rule was copied from any source.
This matters because it means the licence question here is **only** *"what rights do I want to
grant?"* — not *"do I have the right to publish this at all?"*, which is a separate and harder
question that applies to other work.

## 2. Third-party dependencies

| Component | What it is | Licence | Implication |
|---|---|---|---|
| EVTX samples | `mdecrevoisier/EVTX-to-MITRE-Attack` | **CC0-1.0** | Public domain dedication. Redistribution permitted, attribution not legally required — given anyway. Files are **not** committed regardless. |
| PyYAML | runtime dependency | MIT | Permissive. Not vendored — installed from PyPI. |
| GitHub Actions (`checkout`, `setup-python`) | CI | MIT | Not distributed with this code. |
| MITRE ATT&CK identifiers | `T1053.005` etc. | ATT&CK Terms of Use | Free use with attribution. Referenced, not reproduced. |

**No dependency imposes a licence on this repository.** CC0 in particular imposes nothing.

### The one to be careful about, which does not apply here

`SigmaHQ/sigma` rules are published under the **Detection Rule License (DRL) 1.1**, which
requires attribution when rules are redistributed or modified. The GitHub API reports it as
`NOASSERTION` because DRL is not an SPDX-listed licence, so automated licence checks miss it.

`proc_creation_win_schtasks_creation.yml` was read and analysed for study. **It was not copied,
adapted, or used as a base.** The rule in `sigma/` addresses a different, narrower condition
and was written independently. If any SigmaHQ rule is ever vendored into this repository, DRL
attribution becomes mandatory.

## 3. Options

### A — MIT

Maximum reuse; requires attribution and preserves the disclaimer. The default expectation for
a portfolio repository, and the least friction for anyone evaluating the work.

### B — Apache 2.0

Same permissiveness plus an explicit patent grant and a requirement to state changes.
Preferred by some enterprises for that reason. Slightly heavier.

### C — Detection Rule License 1.1

Purpose-built for detection content and what the detection-engineering community uses. Signals
familiarity with the field's conventions. Less familiar to a general reviewer, and covers rules
rather than the Python tooling — which would arguably need a second licence.

### D — No licence

Full copyright retained; the code is readable but not legally reusable. Perfectly acceptable
for a portfolio whose purpose is to demonstrate capability rather than to be adopted. Some
reviewers read it as an unfinished repository; others do not notice.

### E — Dual: DRL for `sigma/`, MIT for everything else

The most technically correct arrangement, and what several detection projects actually do.
Costs a paragraph in the README to explain.

## 4. Recommendation

**Apache 2.0**, if the goal is for this to be evaluated as an engineering portfolio by
employers in Ireland.

Reasoning: it is permissive enough that nobody hesitates, familiar enough that nobody has to
think about it, and the patent grant reads as commercial awareness rather than naivety. The
dual arrangement (E) is more correct in principle, but explaining a licence split on a
repository with one rule in it costs more attention than it earns.

**This is a recommendation, not a decision.** No `LICENSE` file has been created.

## 5. What has to happen before this repository is published

```text
[ ] Gate 0  integrity      tree matches what is documented, CI green on the exact commit
[ ] Gate 1  functionality  tests pass in CI, not only locally
[ ] Gate 2  claims         every statement in the README is supported by an artefact
[ ] Gate 3  disclosure     no secrets, no employer material, third-party licensing verified
[ ] Gate 4  explanation    Marcus can explain every rule and every design decision unaided
[ ] LICENCE decision       this document, section 4 -- human decision
[ ] AUTORIZO PUBLICAR      explicit authorisation -- no automation makes a repository public
```

Gates 0–3 can be closed by preparation. Gates 4, the licence, and the authorisation cannot.
