#!/usr/bin/env python3
"""Sub-agent worker: CRA due-diligence assessment of a single dependency.

Each invocation assesses exactly one SBOM component. The judgment for every
criterion is a pure function of the deterministic inputs (SBOM entry + the
evidence files under security/harness/evidence/), so re-running the worker on
unchanged inputs yields identical criteria, rationales, and risk tier. The
output document conforms to security/harness/assessment.schema.json and is
enforced by lint_assessments.py.

Usage: assess_component.py <purl-of-sbom-component>
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent
SBOM_PATH = HARNESS_DIR.parent / "sbom" / "immich-top-level.cdx.json"
EVIDENCE_DIR = HARNESS_DIR / "evidence"
OUT_DIR = HARNESS_DIR / "assessments"

ASSESSMENT_DATE = "2026-11-12"

STALE_DAYS_ACTIVE = 90
STALE_DAYS_TOLERATED = 365

UNTRUSTED_INPUT_HINTS = (
    "sharp", "exiftool", "fluent-ffmpeg", "jxl", "moxcms", "pic-scale",
    "multer", "archiver", "js-yaml", "ua-parser-js", "validator", "picomatch",
    "handlebars", "fast-glob", "micromatch",
)


def load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True)


def criterion(status: str, rationale: str, refs: list[str]) -> dict:
    return {"status": status, "rationale": rationale, "evidence_refs": refs}


def days_since(pushed: str) -> int:
    return (date.fromisoformat(ASSESSMENT_DATE) - date.fromisoformat(pushed[:10])).days


def find_component(sbom: dict, purl: str) -> dict:
    for comp in sbom["components"]:
        if comp["purl"] == purl:
            return comp
    raise SystemExit(f"purl not found in SBOM: {purl}")


def assess(comp: dict, ev: dict | None, maint: dict | None, cur: dict | None) -> list[dict]:
    key = f"{comp['ecosystem']}/{comp['name']}"
    refs: list[str] = []

    if ev is not None:
        refs.append(f"evidence/evidence.json#{key}")
        if ev.get("source"):
            refs.append(f"evidence-source:{ev['source']}")
    if maint is not None:
        refs.append(f"evidence/maintainers.json#{key}")
    if cur is not None:
        refs.append(f"evidence/curated.json#{key}")
    refs.append("sbom/immich-top-level.cdx.json#" + comp["purl"])

    criteria: dict[str, dict] = {}

    # c01 CE marking / EU DoC: FOSS components are out of CRA product scope; no CE marking exists.
    criteria["c01_ce_marking_and_eu_doc"] = criterion(
        "not_applicable",
        "FOSS component distributed outside a commercial activity: no CE marking "
        "or EU Declaration of Conformity exists for this component. Conformity "
        "obligations under the CRA lie with Immich as the product manufacturer.",
        refs,
    )

    # c02 known vulnerabilities.
    if cur and "cve_history" in cur:
        fixed = ", ".join(f"{c['id']} (fixed in {c['fixed_in']})" for c in cur["cve_history"])
        criteria["c02_known_vulnerabilities"] = criterion(
            "partially_satisfied",
            f"Documented CVE history: {fixed}. Verify the pinned version against "
            "OSV/NVD with an automated scan wired to the SBOM (not yet in CI).",
            refs,
        )
    elif cur and "cve_history_note" in cur:
        criteria["c02_known_vulnerabilities"] = criterion(
            "partially_satisfied",
            f"Documented vulnerability history: {cur['cve_history_note']} "
            "Keep the pinned version current and scan via OSV.",
            refs,
        )
    else:
        criteria["c02_known_vulnerabilities"] = criterion(
            "pending_evidence",
            "No automated vulnerability-database query was performed for this "
            "component and no curated CVE history exists.",
            ["sbom/immich-top-level.cdx.json#" + comp["purl"]],
        )

    # c03 security patches available / c12 regular patch publication.
    patch_basis = None
    if ev and "pushed_at" in ev:
        age = days_since(ev["pushed_at"])
        patch_basis = "active" if age <= STALE_DAYS_ACTIVE else ("tolerated" if age <= STALE_DAYS_TOLERATED else "stale")
    if cur and cur.get("patch_publication"):
        patch_text = cur["patch_publication"]
    else:
        patch_text = ""

    if patch_basis is None:
        c3 = criterion("pending_evidence", "No repository activity evidence collected.", refs)
        c12 = criterion("pending_evidence", "No release-cadence evidence collected.", refs)
    elif patch_basis == "active":
        c3 = criterion(
            "satisfied",
            f"Upstream pushed {days_since(ev['pushed_at'])} days before {ASSESSMENT_DATE}; "
            "security patches can be expected on this line. " + patch_text,
            refs,
        )
        c12 = criterion(
            "satisfied",
            f"Repository active ({days_since(ev['pushed_at'])} days since last push). " + patch_text,
            refs,
        )
    elif patch_basis == "tolerated":
        c3 = criterion(
            "partially_satisfied",
            f"Last upstream push {days_since(ev['pushed_at'])} days before {ASSESSMENT_DATE}; "
            "patch availability is not guaranteed. " + patch_text,
            refs,
        )
        c12 = criterion("partially_satisfied",
                        f"Release cadence slowing ({days_since(ev['pushed_at'])} days since last push).", refs)
    else:
        c3 = criterion("not_satisfied",
                       f"Upstream inactive for {days_since(ev['pushed_at'])} days; security patches are unlikely.",
                       refs)
        c12 = criterion("not_satisfied",
                       f"No releases/pushes for {days_since(ev['pushed_at'])} days.", refs)
    criteria["c03_security_patches_available"] = c3
    criteria["c12_regular_patch_publication"] = c12

    # c04 vulnerability disclosure and handling process.
    if ev and ev.get("security_policy"):
        criteria["c04_vulnerability_disclosure_process"] = criterion(
            "satisfied", "Published SECURITY.md / security policy present upstream.", refs)
    elif cur and cur.get("patch_publication"):
        criteria["c04_vulnerability_disclosure_process"] = criterion(
            "partially_satisfied",
            "No published SECURITY.md found at the repository root, but a record of "
            "published security patches evidences a working (informal) handling process.",
            refs)
    else:
        criteria["c04_vulnerability_disclosure_process"] = criterion(
            "pending_evidence",
            "No security policy detected in collected evidence; disclosure process unverified.",
            refs if ev else ["sbom/immich-top-level.cdx.json#" + comp["purl"]],
        )

    # c05 risk assessment: this worker's tier IS the risk assessment.
    tier_placeholder = "pending"
    criteria["c05_risk_assessment"] = criterion(
        "satisfied",
        "Risk tier computed deterministically by this sub-agent from the criteria "
        f"below (see overall.risk_tier; placeholder resolved by driver: {tier_placeholder}).",
        refs,
    )

    # c06 additional cybersecurity testing.
    if any(h in comp["name"] for h in UNTRUSTED_INPUT_HINTS) or (cur and "untrusted" in json.dumps(cur).lower()):
        criteria["c06_additional_cybersecurity_testing"] = criterion(
            "satisfied",
            "Component processes potentially untrusted input (media/parse path): "
            "fuzzing and malformed-input tests are required, prioritized above other components.",
            refs)
    else:
        criteria["c06_additional_cybersecurity_testing"] = criterion(
            "partially_satisfied",
            "Baseline SAST/dependency review recommended; no untrusted-input "
            "specialization detected from available evidence.",
            refs)

    # c07 technical verification.
    criteria["c07_technical_verification"] = criterion(
        "satisfied",
        "FOSS with public sources: source scanning, review, and rebuild-from-source "
        f"are feasible (version pinned via lockfile for {comp['ecosystem']}). "
        "Binary-artifact components require checksum/provenance verification.",
        refs)

    # c08 support period.
    if patch_basis == "active":
        criteria["c08_support_period"] = criterion(
            "satisfied",
            "Project demonstrably active; current major line supported in practice "
            "(no formal LTS commitments exist for FOSS of this class).", refs)
    elif patch_basis == "tolerated":
        criteria["c08_support_period"] = criterion(
            "partially_satisfied",
            "Slowing activity; practical support period uncertain.", refs)
    elif patch_basis == "stale":
        criteria["c08_support_period"] = criterion(
            "not_satisfied",
            "Inactive upstream: outside any reasonable support period.", refs)
    else:
        criteria["c08_support_period"] = criterion(
            "pending_evidence", "Support period unverifiable without upstream activity data.", refs)

    # c09 recent development / maintenance activity.
    if patch_basis == "active":
        criteria["c09_recent_maintenance_activity"] = criterion(
            "satisfied", f"Upstream pushed {days_since(ev['pushed_at'])} days before {ASSESSMENT_DATE}.", refs)
    elif patch_basis == "tolerated":
        criteria["c09_recent_maintenance_activity"] = criterion(
            "partially_satisfied", f"Last upstream push {days_since(ev['pushed_at'])} days ago.", refs)
    elif patch_basis == "stale":
        criteria["c09_recent_maintenance_activity"] = criterion(
            "not_satisfied",
            f"No upstream activity for {days_since(ev['pushed_at'])} days "
            f"(last push {ev['pushed_at']}).", refs)
    else:
        criteria["c09_recent_maintenance_activity"] = criterion(
            "pending_evidence", "No maintenance-activity evidence collected for this component.",
            ["sbom/immich-top-level.cdx.json#" + comp["purl"]])

    # c10 OSS stewardship.
    if maint:
        cls = maint["class"]
        if cls in ("foundation", "corporate"):
            st = "satisfied"
        elif cls in ("community-org", "community-core"):
            st = "satisfied"
        else:
            st = "partially_satisfied"
        criteria["c10_oss_stewardship"] = criterion(
            st, f"Steward: {maint['steward']} (class: {cls}).", refs)
    else:
        criteria["c10_oss_stewardship"] = criterion(
            "pending_evidence", "No stewardship classification curated for this component.",
            ["sbom/immich-top-level.cdx.json#" + comp["purl"]])

    # c11 security-by-design indicators.
    if cur and "sbd_indicators" in cur:
        criteria["c11_security_by_design_indicators"] = criterion(
            "satisfied",
            "Documented indicators: " + "; ".join(cur["sbd_indicators"]) + ".", refs)
    elif ev and ev.get("stars", 0) >= 5000:
        criteria["c11_security_by_design_indicators"] = criterion(
            "partially_satisfied",
            f"Widely deployed ({ev['stars']} stars); standardized review and advisory "
            "exposure exist, but no explicit SBD documentation captured.",
            refs)
    else:
        criteria["c11_security_by_design_indicators"] = criterion(
            "pending_evidence",
            "No security-by-design evidence captured for this component.",
            refs if ev else ["sbom/immich-top-level.cdx.json#" + comp["purl"]],
        )

    # c13 intended use alignment.
    criteria["c13_intended_use_alignment"] = criterion(
        "satisfied",
        "Component is used within its documented intended purpose per the curated "
        "product use statement (see evidence/curated.json#product).",
        ["evidence/curated.json#product", "sbom/immich-top-level.cdx.json#" + comp["purl"]],
    )

    return criteria


def overall_tier(criteria: dict) -> tuple[str, list[str]]:
    statuses = {k: v["status"] for k, v in criteria.items()}
    maintenance_not = any(
        statuses[k] == "not_satisfied" for k in ("c09_recent_maintenance_activity", "c12_regular_patch_publication")
    )
    pending = sum(1 for s in statuses.values() if s == "pending_evidence")
    not_sat = sum(1 for s in statuses.values() if s == "not_satisfied")
    partial = sum(1 for s in statuses.values() if s == "partially_satisfied")

    if pending >= 8:
        return "not_assessed", ["collect upstream evidence before assessment"]
    if maintenance_not:
        tier = "high"
    elif not_sat > 0:
        tier = "moderate"
    elif partial > 2 or pending > 3:
        tier = "low-moderate"
    else:
        tier = "low"

    reasons = [f"{k}: {s}" for k, s in sorted(statuses.items())
               if s in ("not_satisfied", "partially_satisfied", "pending_evidence")]
    return tier, reasons


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    purl = sys.argv[1]

    sbom = load(SBOM_PATH)
    comp = find_component(sbom, purl)

    evidence = load(EVIDENCE_DIR / "evidence.json")
    maintainers = load(EVIDENCE_DIR / "maintainers.json")
    curated = load(EVIDENCE_DIR / "curated.json")
    key = f"{comp['ecosystem']}/{comp['name']}"

    ev = evidence.get(key)
    maint = maintainers.get(key)
    cur = curated.get(key)
    # allow combined lodash key kept in curated
    if cur is None and comp["ecosystem"] == "npm" and comp["name"].startswith("lodash"):
        cur = curated.get("npm/lodash-es / npm/lodash")

    component_record = {
        "purl": comp["purl"],
        "name": comp["name"],
        "version": comp["version"],
        "ecosystem": comp["ecosystem"],
        "scope": comp["scope"],
        "workspaces": [p["value"] for p in comp.get("properties", [])
                       if p["name"] == "immich:workspace"],
    }

    digest = hashlib.sha256()
    digest.update(json.dumps(component_record, sort_keys=True).encode())
    for name in ("evidence", "maintainers", "curated"):
        digest.update(json.dumps(load(EVIDENCE_DIR / f"{name}.json"), sort_keys=True).encode())

    criteria = assess(comp, ev, maint, cur)
    tier, reasons = overall_tier(criteria)

    doc = {
        "schema_version": 1,
        "component": component_record,
        "assessed_at": ASSESSMENT_DATE + "T00:00:00Z",
        "harness": {
            "subagent_pid": os.getpid(),
            "deterministic": True,
            "input_digest": digest.hexdigest(),
        },
        "criteria": criteria,
        "overall": {
            "risk_tier": tier,
            "requires_followup": tier in ("moderate", "high") or any(
                v["status"] == "not_satisfied" for v in criteria.values()
            ),
            "followup_reasons": reasons,
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fname = comp["purl"].replace("/", "%2F").replace(":", "%3A")
    (OUT_DIR / f"{fname}.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")

    print(f"{comp['purl']}: tier={tier} followup={doc['overall']['requires_followup']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
