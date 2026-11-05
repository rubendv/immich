"""Linter: check the ASVS assessment output against the ASVS source document.

Verifies that the assessment file is a faithful extension of the source:
- same document metadata (Name, ShortName, Version, Description)
- identical requirement tree (shortcodes, ordinals, names, descriptions, levels)
- every L1/L2 leaf carries the four assessment fields with valid values
- L3 leaves carry no assessment fields
- cross-field consistency (e.g. Applicability 'no' requires 'n/a' verdicts)
"""

import json
import sys
from pathlib import Path

BASE = Path(__file__).parent
SOURCE = BASE / "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
OUTPUT = BASE / "ASVS-5.0.0-L1-L2-assessment-immich.json"

ASSESSMENT_FIELDS = ("Applicability", "Implemented", "Tested", "Evidence")
APPLICABILITY_VALUES = {"yes", "no", "partial"}
VERDICT_VALUES = {"yes", "partial", "no", "n/a"}


def flatten(items, path=""):
    """Yield (path, item) for every node in the tree, keyed by shortcode path."""
    for item in items:
        key = f"{path}/{item['Shortcode']}"
        yield key, item
        if "Items" in item:
            yield from flatten(item["Items"], key)


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
            for field in ASSESSMENT_FIELDS:
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
        else:
            counts["L3"] += 1
            for field in ASSESSMENT_FIELDS:
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
