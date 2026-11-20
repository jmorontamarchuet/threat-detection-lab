#!/usr/bin/env python3
"""Validate every detection in detections/.

For each detection folder it checks:
  1. The required files exist (README, simulation, KQL, Sentinel rule, tests).
  2. The Sigma rule (the only *.yml file, named the SigmaHQ way) has the required fields and an ATT&CK tag that matches the folder name.
  3. sentinel_rule.yaml has the required fields and the same technique and rule id.
  4. The Sigma logic fires on every event in tests/positive.json and on none in
     tests/negative.json (a small built-in evaluator, case-insensitive like Sigma).
  5. The Sigma rule converts to KQL for Microsoft Defender XDR with pySigma.
     The generated query is written to build/<folder>.kql.

Exit code is 1 if anything fails, so CI goes red.
"""
import json
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS = ROOT / "detections"
BUILD = ROOT / "build"
REQUIRED_FILES = [
    "README.md",
    "simulation.md",
    "defender_xdr.kql",
    "sentinel_rule.yaml",
    "tests/positive.json",
    "tests/negative.json",
]
SIGMA_KEYS = ["title", "id", "status", "description", "author", "date", "tags",
              "logsource", "detection", "falsepositives", "level"]
SENTINEL_KEYS = ["id", "name", "description", "severity", "queryFrequency", "queryPeriod",
                 "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
                 "query", "entityMappings", "version", "kind"]


# ---------------------------------------------------------------- Sigma evaluator
def _match_value(event_value, pattern, modifiers):
    if event_value is None:
        return False
    value = str(event_value).lower()
    pattern = str(pattern).lower()
    if "contains" in modifiers:
        return pattern in value
    if "startswith" in modifiers:
        return value.startswith(pattern)
    if "endswith" in modifiers:
        return value.endswith(pattern)
    return value == pattern


def _match_field(event, key, expected):
    field, *modifiers = key.split("|")
    unsupported = set(modifiers) - {"contains", "startswith", "endswith", "all"}
    if unsupported:
        raise ValueError(f"unsupported modifier(s) {sorted(unsupported)} in '{key}'")
    patterns = expected if isinstance(expected, list) else [expected]
    results = [_match_value(event.get(field), p, modifiers) for p in patterns]
    return all(results) if "all" in modifiers else any(results)


def _match_selection(event, selection):
    if isinstance(selection, list):  # list of maps = OR
        return any(_match_selection(event, item) for item in selection)
    if isinstance(selection, dict):  # map = AND across fields
        return all(_match_field(event, k, v) for k, v in selection.items())
    raise ValueError(f"unsupported selection type: {type(selection).__name__}")


def evaluate(detection, event):
    names = {k: v for k, v in detection.items() if k != "condition"}
    results = {name: _match_selection(event, sel) for name, sel in names.items()}
    condition = detection["condition"]

    def expand(match):
        quantifier, pattern = match.group(1), match.group(2)
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        hits = [results[n] for n in results if regex.match(n)]
        if not hits:
            raise ValueError(f"'{match.group(0)}' matches no selection")
        return str(all(hits) if quantifier == "all" else any(hits))

    expr = re.sub(r"\b(1|all) of ([\w*]+)", expand, condition)
    tokens = re.findall(r"\(|\)|[\w*]+", expr)
    allowed = {"and", "or", "not", "(", ")", "True", "False"}
    py = []
    for tok in tokens:
        if tok in allowed:
            py.append(tok)
        elif tok in results:
            py.append(str(results[tok]))
        else:
            raise ValueError(f"unknown token '{tok}' in condition")
    return eval(" ".join(py), {"__builtins__": {}})  # only booleans and operators reach here


# ---------------------------------------------------------------- checks
def check_detection(folder: Path):
    errors = []
    technique = folder.name.split("-")[0]  # e.g. T1003.001

    for rel in REQUIRED_FILES:
        if not (folder / rel).exists():
            errors.append(f"missing file {rel}")
    sigma_files = sorted(folder.glob("*.yml"))
    if len(sigma_files) != 1:
        errors.append(f"expected exactly one Sigma rule (*.yml), found {len(sigma_files)}")
    if errors:
        return errors

    sigma_path = sigma_files[0]
    sigma = yaml.safe_load(sigma_path.read_text(encoding="utf-8"))
    for key in SIGMA_KEYS:
        if key not in sigma:
            errors.append(f"{sigma_path.name}: missing '{key}'")
    try:
        uuid.UUID(str(sigma.get("id")))
    except ValueError:
        errors.append(f"{sigma_path.name}: id is not a UUID")
    if f"attack.{technique.lower()}" not in sigma.get("tags", []):
        errors.append(f"{sigma_path.name}: tags must include attack.{technique.lower()}")

    rule = yaml.safe_load((folder / "sentinel_rule.yaml").read_text(encoding="utf-8"))
    for key in SENTINEL_KEYS:
        if key not in rule:
            errors.append(f"sentinel_rule.yaml: missing '{key}'")
    if technique not in rule.get("relevantTechniques", []):
        errors.append(f"sentinel_rule.yaml: relevantTechniques must include {technique}")
    if str(rule.get("id")) != str(sigma.get("id")):
        errors.append("sentinel_rule.yaml: id must match the Sigma rule id")

    for name, expected in (("positive", True), ("negative", False)):
        cases = json.loads((folder / "tests" / f"{name}.json").read_text(encoding="utf-8"))
        if not cases:
            errors.append(f"tests/{name}.json is empty")
        for case in cases:
            try:
                fired = evaluate(sigma["detection"], case["event"])
            except ValueError as exc:
                errors.append(f"{sigma_path.name}: {exc}")
                break
            if fired != expected:
                verb = "did not fire" if expected else "fired"
                errors.append(f"{name} test {verb}: {case['description']}")

    try:
        from sigma.backends.kusto import KustoBackend
        from sigma.collection import SigmaCollection
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

        backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
        rules = SigmaCollection.from_yaml(sigma_path.read_text(encoding="utf-8"))
        queries = backend.convert(rules)
        BUILD.mkdir(exist_ok=True)
        (BUILD / f"{folder.name}.kql").write_text("\n\n".join(queries) + "\n", encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - report any conversion failure
        errors.append(f"{sigma_path.name}: conversion to KQL failed: {exc}")

    return errors


def main():
    folders = sorted(p for p in DETECTIONS.iterdir() if p.is_dir())
    if not folders:
        print("No detections found.")
        return 1
    failed = 0
    for folder in folders:
        errors = check_detection(folder)
        status = "FAIL" if errors else "OK"
        print(f"[{status}] {folder.name}")
        for err in errors:
            print(f"       - {err}")
        failed += bool(errors)
    print(f"\n{len(folders) - failed}/{len(folders)} detections passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
