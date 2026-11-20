# Threat Detection Lab — Detection as Code

![Validate detections](https://github.com/jmorontamarchuet/threat-detection-lab/actions/workflows/validate.yml/badge.svg)

Detections for **Microsoft Defender XDR** and **Microsoft Sentinel**, written once in
**Sigma**, mapped to **MITRE ATT&CK**, and tested automatically on every push.

Each detection ships with:

- a **Sigma rule** — the SIEM-agnostic source of truth,
- a production **KQL query** for Defender XDR and a **Sentinel analytics rule**,
- **positive and negative test events** the rule must fire / not fire on,
- a **benign simulation** with Atomic Red Team to reproduce the technique in a lab,
- documentation: hypothesis, telemetry, known gaps, false positives and a triage guide.

## Coverage

| ATT&CK | Technique | Detection | Severity | Status |
|---|---|---|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | [LSASS dump via comsvcs.dll MiniDump](detections/T1003.001-lsass-dump-comsvcs/) | High | Experimental |

## How the pipeline works

On every push and pull request, GitHub Actions:

1. runs `sigma check` for syntax and rule-quality issues,
2. checks that every detection has all its files and consistent metadata
   (same rule ID and ATT&CK technique across Sigma and Sentinel),
3. runs each Sigma rule against its **positive and negative test events**,
4. converts the Sigma rule to **KQL for Defender XDR** with pySigma and publishes the
   result as a build artifact.

If any step fails, the build goes red and the detection is not considered ready.

## Repository layout

```
detections/
  <ATT&CK ID>-<short-name>/
    <sigma-rule>.yml        Sigma rule (SigmaHQ naming)
    defender_xdr.kql        Defender XDR advanced hunting / custom detection
    sentinel_rule.yaml      Sentinel scheduled analytics rule
    simulation.md           How to reproduce it safely in a lab
    README.md               Hypothesis, logic, gaps, false positives, triage
    tests/
      positive.json         Must fire
      negative.json         Must not fire
tools/validate.py           Structure checks, unit tests, KQL conversion
.github/workflows/          CI
```

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
sigma check detections/
python tools/validate.py
```

## Adding a detection

1. Create `detections/<ATT&CK ID>-<short-name>/` with the files above.
2. Write the test events first: what must fire, and what must not.
3. Write the Sigma rule until `python tools/validate.py` passes.
4. Port the logic to `defender_xdr.kql` and `sentinel_rule.yaml` (same rule ID).
5. Reproduce it in the lab following `simulation.md` and record the result.
6. Add a row to the coverage table.

## Scope

Personal lab project. All test data is synthetic or generated in my own lab;
no client or employer data is used.

## Author

**Jan Moronta Marchuet** — SOC Analyst · Detection Engineering

## License

[MIT](LICENSE)
