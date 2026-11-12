"""Linter: check the ASVS assessment output against the ASVS source document.

Verifies that the assessment file is a faithful extension of the source:
- same document metadata (Name, ShortName, Version, Description)
- identical requirement tree (shortcodes, ordinals, names, descriptions, levels)
- every L1/L2 leaf carries the four assessment fields with valid values
- every L1/L2 leaf carries 'evidence_references' citing existing repo files/lines,
  with codes that are all referenced from the Evidence text
- L3 leaves carry no assessment fields
- cross-field consistency (e.g. Applicability 'no' requires 'n/a' verdicts)
"""

import json
import re
import sys
from pathlib import Path

BASE = Path(__file__).parent
REPO = BASE.parent
SOURCE = BASE / "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
OUTPUT = BASE / "ASVS-5.0.0-L1-L2-assessment-immich.json"

ASSESSMENT_FIELDS = ("Applicability", "Implemented", "Tested", "Evidence")
APPLICABILITY_VALUES = {"yes", "no", "partial"}
VERDICT_VALUES = {"yes", "partial", "no", "n/a"}
EVIDENCE_CODE_PATTERN = re.compile(r"\[(E\d+(?:,\s*E\d+)*)\]")
REFERENCE_PATTERN = re.compile(r"^(?P<path>[^:]+):(?P<line>[0-9]+)$")


def flatten(items, path=""):
    """Yield (path, item) for every node in the tree, keyed by shortcode path."""
    for item in items:
        key = f"{path}/{item['Shortcode']}"
        yield key, item
        if "Items" in item:
            yield from flatten(item["Items"], key)


def check_references(key: str, evidence: str, references: object, errors: list[str]) -> None:
    """Validate the evidence_references mapping of an L1/L2 requirement."""
    if not isinstance(references, dict) or not references:
        errors.append(f"{key}: 'evidence_references' must be a non-empty object")
        return

    for code, reference in references.items():
        if not re.fullmatch(r"E[0-9]+", code):
            errors.append(f"{key}: invalid evidence code {code!r} (expected 'E<number>')")
        if not isinstance(reference, str):
            errors.append(f"{key}: {code} reference must be a string")
            continue
        match = REFERENCE_PATTERN.match(reference)
        if not match:
            errors.append(f"{key}: {code} reference {reference!r} does not match '<file>:<line>'")
            continue
        path = REPO / match.group("path")
        if not path.is_file():
            errors.append(f"{key}: {code} reference {reference!r} points to a non-existent file")
            continue
        line = int(match.group("line"))
        line_count = sum(1 for _ in path.open(encoding="utf-8", errors="replace"))
        if not 1 <= line <= line_count:
            errors.append(f"{key}: {code} reference {reference!r} line {line} out of range (file has {line_count} lines)")

    cited = set()
    for group in EVIDENCE_CODE_PATTERN.findall(evidence or ""):
        cited.update(code.strip() for code in group.split(","))
    for code in references:
        if code not in cited:
            errors.append(f"{key}: evidence code {code} is not cited in Evidence")
    for code in sorted(cited, key=lambda c: int(c[1:])):
        if code not in references:
            errors.append(f"{key}: Evidence cites {code} which is missing from 'evidence_references'")


def main():
    errors = []
    source = json.loads(SOURCE.read_text())
    output = json.loads(OUTPUT.read_text())

    for field in ("Name", "ShortName", "Version", "Description"):
        if output.get(field) != source.get(field):
            errors.append(f"top-level '{field}' differs from source")

    if "Assessment" not in output:
        errors.append("missing top-level 'Assessment' metadata")
    else:
        for field in ("Project", "Level", "Scope", "Legend"):
            if field not in output["Assessment"]:
                errors.append(f"Assessment metadata missing '{field}'")

    src_nodes = dict(flatten(source["Requirements"]))
    out_nodes = dict(flatten(output["Requirements"]))

    for key, src in src_nodes.items():
        out = out_nodes.get(key)
        if out is None:
            errors.append(f"{key}: missing from assessment")
            continue
        for field in ("Shortcode", "Ordinal", "L"):
            if out.get(field) != src.get(field):
                errors.append(f"{key}: '{field}' differs from source")
        for field in ("Name", "Description"):
            if field in src and out.get(field) != src.get(field):
                errors.append(f"{key}: '{field}' differs from source")
        if "Items" in src and "Items" not in out:
            errors.append(f"{key}: missing child 'Items'")
        if "Items" not in src and "Items" in out:
            errors.append(f"{key}: unexpected child 'Items'")

    for key in out_nodes:
        if key not in src_nodes:
            errors.append(f"{key}: not present in source")

    counts = {"L1": 0, "L2": 0, "L3": 0}
    for key, src in src_nodes.items():
        if "Items" in src:
            continue
        level = src.get("L")
        out = out_nodes.get(key, {})
        if level in ("1", "2"):
            counts[f"L{level}"] += 1
            for field in ASSESSMENT_FIELDS + ("evidence_references",):
                if field not in out:
                    errors.append(f"{key}: L{level} requirement missing '{field}'")
            applicability = out.get("Applicability")
            implemented = out.get("Implemented")
            tested = out.get("Tested")
            evidence = out.get("Evidence")
            if applicability not in APPLICABILITY_VALUES:
                errors.append(f"{key}: invalid Applicability {applicability!r}")
            if implemented not in VERDICT_VALUES:
                errors.append(f"{key}: invalid Implemented {implemented!r}")
            if tested not in VERDICT_VALUES:
                errors.append(f"{key}: invalid Tested {tested!r}")
            if not isinstance(evidence, str) or not evidence.strip():
                errors.append(f"{key}: empty Evidence")
            if applicability == "no":
                if implemented != "n/a" or tested != "n/a":
                    errors.append(f"{key}: Applicability 'no' but Implemented/Tested not 'n/a'")
            else:
                if implemented == "n/a" or tested == "n/a":
                    errors.append(f"{key}: applicable requirement must not use 'n/a' verdicts")
            check_references(key, evidence, out.get("evidence_references"), errors)
        else:
            counts["L3"] += 1
            for field in ASSESSMENT_FIELDS + ("evidence_references",):
                if field in out:
                    errors.append(f"{key}: L3 requirement must not carry '{field}'")

    print(f"L1: {counts['L1']} assessed, L2: {counts['L2']} assessed, L3: {counts['L3']} unassessed")
    if errors:
        print(f"\n{len(errors)} error(s):")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    print("OK: assessment is consistent with the source document")


if __name__ == "__main__":
    main()
