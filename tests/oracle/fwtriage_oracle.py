"""M1 and M2: sarif-writer against fwtriage's output/sarif.py, and every output against the schema.

usage: FWTRIAGE/.venv/bin/python tests/oracle/fwtriage_oracle.py SARW_LINES FWTRIAGE WORKDIR

For each scenario of the fwtriage corpus (tests/corpus/scenarios.py) the image is scanned and
the report rendered by fwtriage (render). The same document, read back from to_dict, is fed to
SARW_LINES (tests/sarw_lines.c), which writes it with sarif-writer: M2 compares the two byte by byte.
Artifact URIs go in as paths, so sarif-writer normalizes and percent-encodes them. Then a document that
uses every field sarif-writer writes (FEATURES below) is written. M1: every document sarif-writer wrote
validates against FWTRIAGE/tests/data/sarif-schema-2.1.0.json. Exits 1 on any difference.
"""

import json
import subprocess
import sys
from pathlib import Path

LEVELS = {None: 0, "none": 1, "note": 2, "warning": 3, "error": 4}

def h(value) -> str:
    if value is None:
        return "-"
    return str(value).encode().hex() or "="

def line(*fields) -> str:
    return " ".join(fields) + "\n"

def props(pairs: dict) -> list[str]:
    out = [h(len(pairs))]
    for key, value in pairs.items():
        out += [h(key), h(value)]
    return out

def location(loc: dict) -> list[str]:
    physical = loc.get("physicalLocation", {})
    art = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    logical = loc.get("logicalLocations", [{}])[0].get("fullyQualifiedName")
    offset = region.get("byteOffset")
    return [
        h(art.get("uri")), "-", h(art.get("uriBaseId")),
        h(region.get("startLine", 0)), h(region.get("startColumn", 0)), h(region.get("endLine", 0)),
        h(region.get("endColumn", 0)), h(int(offset is not None)), h(offset or 0), h(region.get("byteLength", 0)),
        h(logical), h(loc.get("message", {}).get("text")),
    ]

def text(obj: dict, key: str):
    return obj.get(key, {}).get("text")

def rule_line(r: dict) -> str:
    p = dict(r.get("properties", {}))
    tags = p.pop("tags", [])
    level = r.get("defaultConfiguration", {}).get("level")
    return line(
        "R", h(r["id"]), h(r.get("name")), h(text(r, "shortDescription")), h(text(r, "fullDescription")),
        h(text(r, "help")), h(LEVELS[level]), h(len(tags)), *map(h, tags), *props(p), h(r.get("helpUri")),
    )

def result_line(r: dict) -> str:
    locs = r.get("locations", [])
    rel = r.get("relatedLocations", [])
    fields = ["S", h(r["ruleId"]), h(r.get("ruleIndex")), h(LEVELS[r.get("level")]), h(r["message"]["text"])]
    fields += [h(len(locs))] + [f for loc in locs for f in location(loc)]
    fields += [h(len(rel))] + [f for loc in rel for f in location(loc)]
    return line(*fields, *props(r.get("partialFingerprints", {})), *props(r.get("properties", {})))

def tail_line(run: dict) -> str:
    arts = [{"physicalLocation": {"artifactLocation": a["location"]}} for a in run.get("artifacts", [])]
    fields = ["E", h(len(arts))] + [f for a in arts for f in location(a)]
    inv = run.get("invocations", [])
    if not inv:
        return line(*fields, h(0))
    i = inv[0]
    notes = i.get("toolExecutionNotifications", [])
    fields += [h(1), h(i.get("commandLine")), h(int(i["executionSuccessful"])), h(len(notes))]
    for n in notes:
        fields += [h(LEVELS[n.get("level")]), h(n["message"]["text"])]
    return line(*fields)

def lines_of(doc: dict) -> str:
    out = []
    for run in doc["runs"]:
        d = run["tool"]["driver"]
        out.append(line("T", h(d["name"]), h(d.get("version")), h(d.get("informationUri"))))
        out += [rule_line(r) for r in d.get("rules", [])]
        out += [result_line(r) for r in run["results"]]
        out.append(tail_line(run))
    out.append("F\n")
    return "".join(out)

FEATURES = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "a", "version": "1.0", "informationUri": "https://example.com/a", "rules": [
                {"id": "A1", "name": "One", "shortDescription": {"text": "s"}, "fullDescription": {"text": "f"},
                 "help": {"text": "h"}, "defaultConfiguration": {"level": "warning"},
                 "properties": {"tags": ["security", "external/cwe/cwe-798"], "precision": "high"},
                 "helpUri": "https://example.com/A1"},
                {"id": "A2"},
            ]}},
            "results": [
                {"ruleId": "A1", "ruleIndex": 0, "level": "note", "message": {"text": "q\"\\\n\t\u0001 é"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a b.c", "uriBaseId": "SRC"},
                                                     "region": {"startLine": 1, "startColumn": 2, "endLine": 3,
                                                                "endColumn": 4, "byteOffset": 0, "byteLength": 9}},
                                "logicalLocations": [{"fullyQualifiedName": "f"}]}],
                 "relatedLocations": [{"physicalLocation": {"artifactLocation": {"uri": "/etc/x"}},
                                       "message": {"text": "here"}}],
                 "partialFingerprints": {"a/v1": "00ff"}, "properties": {"confidence": "high"}},
                {"ruleId": "A2", "message": {"text": ""}},
            ],
            "artifacts": [{"location": {"uri": "src/a b.c", "uriBaseId": "SRC"}}],
            "invocations": [{"commandLine": "a --all", "executionSuccessful": False,
                             "toolExecutionNotifications": [{"level": "error", "message": {"text": "x"}}]}],
        },
        {"tool": {"driver": {"name": "b"}}, "results": []},
    ],
}

def write(tool: Path, lines: str) -> str:
    out = subprocess.run([str(tool)], input=lines.encode(), capture_output=True, check=False)
    if out.returncode != 0:
        raise SystemExit(f"sarw_lines failed: {out.stderr.decode()}")
    return out.stdout.decode()

def main(args: list[str]) -> int:
    if len(args) != 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    tool, fwtriage, workdir = Path(args[0]), Path(args[1]), Path(args[2])
    workdir.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(fwtriage))
    import jsonschema
    from fwtriage.app import scan
    from fwtriage.model import Policy
    from fwtriage.output.sarif import render, to_dict
    from tests.corpus.scenarios import SCENARIOS

    schema = json.loads((fwtriage / "tests/data/sarif-schema-2.1.0.json").read_text())
    validator = jsonschema.Draft7Validator(schema)
    same = differ = valid = results = 0
    for scenario in SCENARIOS:
        image = workdir / f"{scenario.name}.image"
        image.write_bytes(scenario.build())
        report = scan(image, Policy(limits=scenario.limits))
        image.unlink()
        theirs = render(report)
        mine = write(tool, lines_of(to_dict(report)))
        results += len(report.findings)
        if mine == theirs:
            same += 1
        else:
            differ += 1
            (workdir / f"{scenario.name}.fwtriage.sarif").write_text(theirs)
            (workdir / f"{scenario.name}.sarif-writer.sarif").write_text(mine)
            print("DIFFERS:", scenario.name)
        valid += not list(validator.iter_errors(json.loads(mine)))
    features = write(tool, lines_of(FEATURES))
    (workdir / "features.sarif").write_text(features)
    errors = list(validator.iter_errors(json.loads(features)))
    for e in errors:
        print("SCHEMA features:", e.message)
    print(f"scenarios {len(SCENARIOS)}, results {results}: identical {same}, different {differ}")
    print(f"schema: {valid + (not errors)} of {len(SCENARIOS) + 1} documents valid")
    return 1 if differ or errors or valid != len(SCENARIOS) else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
