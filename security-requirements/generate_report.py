"""Generate a human-readable Markdown report from the ASVS assessment JSON.

Reads ASVS-5.0.0-L1-L2-assessment-immich.json and writes
ASVS-5.0.0-L1-L2-assessment-immich.md with:
- assessment metadata, verdict summary and legend
- one section per chapter/requirement
- every evidence citation ([E1], [E2], ...) rendered as a clickable GitHub link
  to the referenced file and line

Usage: python3 generate_report.py [--ref <git-ref>]
The default ref for links is 'main'; pass a branch, tag or commit SHA to override.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

BASE = Path(__file__).parent
INPUT = BASE / "ASVS-5.0.0-L1-L2-assessment-immich.json"
OUTPUT = BASE / "ASVS-5.0.0-L1-L2-assessment-immich.md"
REPO_URL = "https://github.com/rubendv/immich"

CITATION_PATTERN = re.compile(r"\[(E\d+(?:,\s*E\d+)*)\]")


def github_link(reference: str, ref: str) -> str:
    path, _, line = reference.rpartition(":")
    return f"{REPO_URL}/blob/{ref}/{quote(path)}#L{line}"


def link_citations(text: str, references: dict[str, str], ref: str) -> str:
    def replace(match: re.Match) -> str:
        links = []
        for code in [c.strip() for c in match.group(1).split(",")]:
            reference = references.get(code)
            if reference is None:
                links.append(code)
                continue
            links.append(f"[{code}]({github_link(reference, ref)})")
        return f"[{', '.join(links)}]"

    return CITATION_PATTERN.sub(replace, text)


def verdict_summary(requirements: list[dict]) -> list[tuple[str, dict[str, int]]]:
    fields = ("Applicability", "Implemented", "Tested")
    counters: dict[str, dict[str, int]] = {field: {} for field in fields}
    for requirement in requirements:
        for field in fields:
            value = requirement.get(field, "unassessed")
            counters[field][value] = counters[field].get(value, 0) + 1
    return [(field, counters[field]) for field in fields]


def collect(requirements: list[dict]) -> list[dict]:
    """Flatten the requirement tree in document order."""
    flat = []
    for chapter in requirements:
        for section in chapter.get("Items", []):
            for leaf in section.get("Items", []):
                flat.append(leaf)
    return flat


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="main", help="git ref used for GitHub links")
    args = parser.parse_args()

    data = json.loads(INPUT.read_text())
    assessment = data["Assessment"]
    leaves = collect(data["Requirements"])
    assessed = [leaf for leaf in leaves if leaf.get("L") in ("1", "2")]

    lines: list[str] = []
    lines.append(f"# ASVS {data['Version']} {assessment['Level']} assessment — {assessment['Project']}")
    lines.append("")
    lines.append(f"Source standard: {data['Name']} v{data['Version']}. Assessed against `{assessment['Repository']}`.")
    lines.append("")
    lines.append(f"**Scope.** {assessment['Scope']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"{len(assessed)} requirements assessed (L1 + L2).")
    lines.append("")
    lines.append("| Verdict | Values |")
    lines.append("| --- | --- |")
    for field, counts in verdict_summary(assessed):
        values = ", ".join(f"{value}: {count}" for value, count in sorted(counts.items()))
        lines.append(f"| {field} | {values} |")
    lines.append("")

    lines.append("## Legend")
    lines.append("")
    for field, description in assessment["Legend"].items():
        lines.append(f"- **{field}**: {description}")
    lines.append("")

    lines.append("## Requirements")
    lines.append("")
    for chapter in data["Requirements"]:
        chapter_title = f"V{chapter['Ordinal']} — {chapter['Name']}"
        lines.append(f"## {chapter_title}")
        lines.append("")
        for section in chapter.get("Items", []):
            lines.append(f"### {section['Shortcode']} {section['Name']}")
            lines.append("")
            for leaf in section.get("Items", []):
                is_assessed = leaf.get("L") in ("1", "2")
                lines.append(f"#### {leaf['Shortcode']} (L{leaf['L']})")
                lines.append("")
                lines.append(f"> {leaf['Description']}")
                lines.append("")
                if is_assessed:
                    lines.append(
                        f"**Applicability:** {leaf['Applicability']} | "
                        f"**Implemented:** {leaf['Implemented']} | "
                        f"**Tested:** {leaf['Tested']}"
                    )
                    lines.append("")
                    references = leaf.get("evidence_references", {})
                    lines.append(f"{link_citations(leaf['Evidence'], references, args.ref)}")
                    lines.append("")
                    if references:
                        entries = ", ".join(
                            f"[{code}]({github_link(reference, args.ref)}) `{reference}`"
                            for code, reference in references.items()
                        )
                        lines.append(f"*References:* {entries}")
                        lines.append("")
                else:
                    lines.append("*Unassessed (Level 3).*")
                    lines.append("")

    OUTPUT.write_text("\n".join(lines))
    print(f"wrote {OUTPUT} ({len(assessed)} assessed requirements, links use ref {args.ref!r})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
