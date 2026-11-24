#!/usr/bin/env python3
"""Linter for per-dependency CRA assessment documents.

Validates every JSON document under security/harness/assessments/ against
security/harness/assessment.schema.json plus structural invariants that a JSON
Schema alone cannot express. Exits non-zero on the first category of failure so
it can gate CI.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    print("FATAL: jsonschema is required (pip install jsonschema)", file=sys.stderr)
    sys.exit(2)

HARNESS_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = HARNESS_DIR / "assessment.schema.json"
SBOM_PATH = HARNESS_DIR.parent / "sbom" / "immich-top-level.cdx.json"
ASSESSMENTS_DIR = HARNESS_DIR / "assessments"

# Fields of the evidence record that feed the input digest computed by the worker.
DIGEST_FIELDS = ("evidence", "maintainers", "curated", "llm_analysis")


def load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def file_digest(*parts) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8") if isinstance(part, str) else part)
    return digest.hexdigest()


def sbom_index():
    sbom = load(SBOM_PATH)
    return {c["purl"]: c for c in sbom["components"]}


def main() -> int:
    schema = load(SCHEMA_PATH)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    sbom = sbom_index()

    failures: list[str] = []
    docs = sorted(ASSESSMENTS_DIR.glob("*.json"))
    seen_purls: set[str] = set()

    if not docs:
        print("FATAL: no assessment documents found", file=sys.stderr)
        return 2

    for doc_path in docs:
        label = doc_path.name
        try:
            doc = load(doc_path)
        except json.JSONDecodeError as err:
            failures.append(f"{label}: invalid JSON ({err})")
            continue

        for err in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.path))):
            failures.append(f"{label}: schema violation at {list(err.path)}: {err.message}")

        if isinstance(doc, dict) and "component" in doc:
            purl = doc["component"].get("purl", "")
            if purl in seen_purls:
                failures.append(f"{label}: duplicate assessment for {purl}")
            seen_purls.add(purl)
            if purl and purl not in sbom:
                failures.append(f"{label}: purl {purl} is not present in the SBOM")
            elif purl:
                sbom_c = sbom[purl]
                for field in ("name", "version", "ecosystem", "scope"):
                    if doc["component"][field] != sbom_c[field]:
                        failures.append(
                            f"{label}: {field} mismatch between assessment and SBOM"
                        )
                if doc["component"]["workspaces"] != [
                    p["value"]
                    for p in sbom_c.get("properties", [])
                    if p["name"] == "immich:workspace"
                ]:
                    failures.append(f"{label}: workspaces mismatch between assessment and SBOM")

        if isinstance(doc, dict) and "harness" in doc and "criteria" in doc:
            digest = file_digest(
                json.dumps(doc["component"], sort_keys=True),
                *(
                    json.dumps(load(HARNESS_DIR / "evidence" / f"{name}.json"), sort_keys=True)
                    for name in DIGEST_FIELDS
                ),
            )
            if doc["harness"].get("input_digest") != digest:
                failures.append(
                    f"{help_issue(label, doc['harness'].get('input_digest'), digest)}"
                )

        if isinstance(doc, dict) and "criteria" in doc:
            pending = [
                key
                for key, criterion in doc["criteria"].items()
                if criterion.get("status") == "pending_evidence"
                and not criterion.get("evidence_refs")
            ]
            if pending:
                failures.append(f"{label}: pending_evidence criteria must cite evidence_refs: {pending}")

    if failures:
        for failure in failures:
            print(f"ERROR {failure}", file=sys.stderr)
        print(f"lint failed: {len(failures)} error(s) across {len(docs)} document(s)")
        return 1

    print(f"lint passed: {len(docs)} document(s) valid against schema {schema['$id']}")
    return 0


def help_issue(label: str, actual, expected) -> str:
    return f"{label}: input_digest mismatch (document {actual!r}, recomputed {expected!r})"


if __name__ == "__main__":
    sys.exit(main())
