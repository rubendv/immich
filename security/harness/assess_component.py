#!/usr/bin/env python3
"""Sub-agent worker: CRA due-diligence assessment of a single dependency.

Each invocation assesses exactly one SBOM component. The analysis layer is an
LLM, not a rule engine:

  1. If the component has an LLM-authored analysis bundle in
     evidence/llm_analysis.json, its per-criterion judgments and rationales are
     used (analyzer.kind = "llm").
  2. Otherwise, if MISTRAL_API_KEY is set, the worker prompts the Mistral API
     (JSON mode) to produce the same bundle on the fly (analyzer.kind = "llm",
     model recorded).
  3. Only when neither is available does it fall back to deterministic rules
     (analyzer.kind = "rules") so the harness never fails silently; the
     analyzer field makes the provenance explicit and lint-visible.

The output document conforms to security/harness/assessment.schema.json and is
enforced by lint_assessments.py (schema + SBOM cross-checks + input digest).

Usage: assess_component.py <purl-of-sbom-component>
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import date
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent
SBOM_PATH = HARNESS_DIR.parent / "sbom" / "immich-top-level.cdx.json"
EVIDENCE_DIR = HARNESS_DIR / "evidence"
OUT_DIR = HARNESS_DIR / "assessments"
SCHEMA_PATH = HARNESS_DIR / "assessment.schema.json"

ASSESSMENT_DATE = "2026-11-12"
STALE_DAYS_ACTIVE = 90
STALE_DAYS_TOLERATED = 365

CRITERION_ORDER = [
    "c01_ce_marking_and_eu_doc",
    "c02_known_vulnerabilities",
    "c03_security_patches_available",
    "c04_vulnerability_disclosure_process",
    "c05_risk_assessment",
    "c06_additional_cybersecurity_testing",
    "c07_technical_verification",
    "c08_support_period",
    "c09_recent_maintenance_activity",
    "c10_oss_stewardship",
    "c11_security_by_design_indicators",
    "c12_regular_patch_publication",
    "c13_intended_use_alignment",
]

UNTRUSTED_INPUT_HINTS = (
    "sharp", "exiftool", "fluent-ffmpeg", "jxl", "moxcms", "pic-scale",
    "multer", "archiver", "js-yaml", "ua-parser-js", "validator", "picomatch",
    "handlebars", "fast-glob", "micromatch", "fabric", "orjson",
)


def load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def find_component(sbom: dict, purl: str) -> dict:
    for comp in sbom["components"]:
        if comp["purl"] == purl:
            return comp
    raise SystemExit(f"purl not found in SBOM: {purl}")


def days_since(pushed: str) -> int:
    return (date.fromisoformat(ASSESSMENT_DATE) - date.fromisoformat(pushed[:10])).days


def evidence_refs(comp: dict, ev: dict | None, maint: dict | None, cur: dict | None) -> list[str]:
    key = f"{comp['ecosystem']}/{comp['name']}"
    refs = ["sbom/immich-top-level.cdx.json#" + comp["purl"]]
    if ev is not None:
        refs.insert(0, f"evidence/evidence.json#{key}")
        if ev.get("source"):
            refs.append(f"evidence-source:{ev['source']}")
    if maint is not None:
        refs.append(f"evidence/maintainers.json#{key}")
    if cur is not None:
        refs.append(f"evidence/curated.json#{key}")
    refs.append("evidence/llm_analysis.json#" + key)
    return refs


# --------------------------------------------------------------------------
# LLM analysis: authored bundle or live API
# --------------------------------------------------------------------------

def build_llm_criteria(bundle, comp, refs) -> dict:
    """Expand an LLM analysis bundle into schema-valid criterion objects."""
    entry, statuses = bundle
    notes = entry.get("criterion_notes", {})
    criteria = {}
    for crit in CRITERION_ORDER:
        status = statuses[crit]
        note = notes.get(crit, "")
        parts = [entry["assessment"]]
        if status == "pending_evidence":
            parts.append("Upstream evidence pending collection for a firm conclusion on this criterion.")
        if note:
            parts.append(note)
        criteria[crit] = {
            "status": status,
            "rationale": " ".join(parts),
            "evidence_refs": refs,
        }
    return criteria


def prompt_for(comp: dict, ev: dict | None, maint: dict | None, cur: dict | None) -> str:
    return (
        "You are a CRA due-diligence sub-agent. Assess the dependency below against the 13 "
        "criteria (c01..c13) defined in the schema: CE marking/EU DoC, known vulnerabilities, "
        "security-patch availability, vulnerability-disclosure process, risk assessment, need "
        "for additional cybersecurity testing, technical verification, support period, recent "
        "maintenance activity, OSS stewardship, security-by-design indicators, regular patch "
        "publication, intended-use alignment. Reply with strict JSON: "
        '{"statuses": {"c01_...": "satisfied|partially_satisfied|not_satisfied|not_applicable|pending_evidence", ...}, '
        '"assessment": "one-sentence judgment", "criterion_notes": {"cXX_...": "optional"}}. '
        "Use status pending_evidence when the data is insufficient. Available evidence:\n"
        + json.dumps({"component": {"purl": comp["purl"], "scope": comp["scope"]},
                      "upstream_activity": ev, "stewardship": maint, "curated_facts": cur},
                     default=str)
    )


def call_mistral_api(prompt: str) -> dict | None:
    """Live LLM analysis via the Mistral API (JSON mode). Returns a bundle or None."""
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        return None
    try:
        import urllib.request

        model = os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
        req = urllib.request.Request(
            "https://api.mistral.ai/v1/chat/completions",
            data=json.dumps({
                "model": model,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "user", "content": prompt}],
            }).encode(),
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.load(resp)
        content = payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if set(parsed.get("statuses", {})) != set(CRITERION_ORDER):
            return None
        parsed["assessment"] = parsed.get("assessment") or "LLM API analysis"
        return parsed, {c: parsed["statuses"][c] for c in CRITERION_ORDER}, model
    except Exception as err:  # noqa: BLE001 - fall back to rules on any API problem
        print(f"mistral api unavailable ({err}); using rules fallback", file=sys.stderr)
        return None


# --------------------------------------------------------------------------
# Deterministic rules fallback (unchanged logic, analyzer kind "rules")
# --------------------------------------------------------------------------

def rule_criteria(comp, ev, maint, cur, refs):
    criteria = {}
    key = f"{comp['ecosystem']}/{comp['name']}"

    criteria["c01_ce_marking_and_eu_doc"] = {
        "status": "not_applicable",
        "rationale": ("FOSS component distributed outside a commercial activity: no CE marking "
                      "or EU Declaration of Conformity exists for this component. Conformity "
                      "obligations under the CRA lie with Immich as the product manufacturer."),
        "evidence_refs": refs,
    }

    if cur and "cve_history" in cur:
        fixed = ", ".join(f"{c['id']} (fixed in {c['fixed_in']})" for c in cur["cve_history"])
        criteria["c02_known_vulnerabilities"] = {
            "status": "partially_satisfied",
            "rationale": f"Documented CVE history: {fixed}. Verify the pinned version against OSV/NVD.",
            "evidence_refs": refs,
        }
    elif cur and "cve_history_note" in cur:
        criteria["c02_known_vulnerabilities"] = {
            "status": "partially_satisfied",
            "rationale": f"Documented vulnerability history: {cur['cve_history_note']}",
            "evidence_refs": refs,
        }
    else:
        criteria["c02_known_vulnerabilities"] = {
            "status": "pending_evidence",
            "rationale": "No automated vulnerability-database query was performed and no curated CVE history exists.",
            "evidence_refs": ["sbom/immich-top-level.cdx.json#" + comp["purl"]],
        }

    patch_basis = None
    if ev and "pushed_at" in ev:
        age = days_since(ev["pushed_at"])
        patch_basis = "active" if age <= STALE_DAYS_ACTIVE else ("tolerated" if age <= STALE_DAYS_TOLERATED else "stale")

    if patch_basis == "active":
        criteria["c03_security_patches_available"] = {"status": "satisfied",
            "rationale": f"Upstream pushed {days_since(ev['pushed_at'])} days before {ASSESSMENT_DATE}; patches can be expected.", "evidence_refs": refs}
        criteria["c12_regular_patch_publication"] = {"status": "satisfied",
            "rationale": f"Repository active ({days_since(ev['pushed_at'])} days since last push).", "evidence_refs": refs}
        criteria["c08_support_period"] = {"status": "satisfied",
            "rationale": "Project demonstrably active; current major supported in practice (no formal LTS for FOSS of this class).", "evidence_refs": refs}
        criteria["c09_recent_maintenance_activity"] = {"status": "satisfied",
            "rationale": f"Upstream pushed {days_since(ev['pushed_at'])} days before {ASSESSMENT_DATE}.", "evidence_refs": refs}
    elif patch_basis == "tolerated":
        criteria["c03_security_patches_available"] = {"status": "partially_satisfied",
            "rationale": f"Last upstream push {days_since(ev['pushed_at'])} days ago; patch availability not guaranteed.", "evidence_refs": refs}
        criteria["c12_regular_patch_publication"] = {"status": "partially_satisfied",
            "rationale": f"Release cadence slowing ({days_since(ev['pushed_at'])} days since last push).", "evidence_refs": refs}
        criteria["c08_support_period"] = {"status": "partially_satisfied",
            "rationale": "Slowing activity; practical support period uncertain.", "evidence_refs": refs}
        criteria["c09_recent_maintenance_activity"] = {"status": "partially_satisfied",
            "rationale": f"Last upstream push {days_since(ev['pushed_at'])} days ago.", "evidence_refs": refs}
    elif patch_basis == "stale":
        criteria["c03_security_patches_available"] = {"status": "not_satisfied",
            "rationale": f"Upstream inactive for {days_since(ev['pushed_at'])} days; security patches unlikely.", "evidence_refs": refs}
        criteria["c12_regular_patch_publication"] = {"status": "not_satisfied",
            "rationale": f"No releases/pushes for {days_since(ev['pushed_at'])} days.", "evidence_refs": refs}
        criteria["c08_support_period"] = {"status": "not_satisfied",
            "rationale": "Inactive upstream: outside any reasonable support period.", "evidence_refs": refs}
        criteria["c09_recent_maintenance_activity"] = {"status": "not_satisfied",
            "rationale": f"No upstream activity for {days_since(ev['pushed_at'])} days (last push {ev['pushed_at']}).", "evidence_refs": refs}
    else:
        for crit in ("c03_security_patches_available", "c12_regular_patch_publication",
                     "c08_support_period", "c09_recent_maintenance_activity"):
            criteria[crit] = {"status": "pending_evidence",
                              "rationale": "No repository activity evidence collected.",
                              "evidence_refs": ["sbom/immich-top-level.cdx.json#" + comp["purl"]]}

    if ev and ev.get("security_policy"):
        criteria["c04_vulnerability_disclosure_process"] = {"status": "satisfied",
            "rationale": "Published SECURITY.md / security policy present upstream.", "evidence_refs": refs}
    elif cur and cur.get("patch_publication"):
        criteria["c04_vulnerability_disclosure_process"] = {"status": "partially_satisfied",
            "rationale": "No published SECURITY.md found, but published security patches evidence an informal handling process.", "evidence_refs": refs}
    else:
        criteria["c04_vulnerability_disclosure_process"] = {"status": "pending_evidence",
            "rationale": "No security policy detected in collected evidence; disclosure process unverified.",
            "evidence_refs": ["sbom/immich-top-level.cdx.json#" + comp["purl"]]}

    criteria["c05_risk_assessment"] = {"status": "satisfied",
        "rationale": "Risk tier computed deterministically from these criteria (see overall.risk_tier).",
        "evidence_refs": refs}

    if any(h in comp["name"] for h in UNTRUSTED_INPUT_HINTS):
        criteria["c06_additional_cybersecurity_testing"] = {"status": "satisfied",
            "rationale": "Component processes potentially untrusted input: fuzzing and malformed-input tests required.",
            "evidence_refs": refs}
    else:
        criteria["c06_additional_cybersecurity_testing"] = {"status": "partially_satisfied",
            "rationale": "Baseline SAST/dependency review recommended.",
            "evidence_refs": refs}

    criteria["c07_technical_verification"] = {"status": "satisfied",
        "rationale": (f"FOSS with public sources: source scanning, review and rebuild-from-source are feasible "
                     f"(version pinned via lockfile for {comp['ecosystem']}). Binary-artifact components need checksum/provenance verification."),
        "evidence_refs": refs}

    if maint:
        cls = maint["class"]
        status = "satisfied" if cls in ("foundation", "corporate", "community-org", "community-core") else "partially_satisfied"
        criteria["c10_oss_stewardship"] = {"status": status,
            "rationale": f"Steward: {maint['steward']} (class: {cls}).", "evidence_refs": refs}
    else:
        criteria["c10_oss_stewardship"] = {"status": "pending_evidence",
            "rationale": "No stewardship classification curated for this component.",
            "evidence_refs": ["sbom/immich-top-level.cdx.json#" + comp["purl"]]}

    if cur and "sbd_indicators" in cur:
        criteria["c11_security_by_design_indicators"] = {"status": "satisfied",
            "rationale": "Documented indicators: " + "; ".join(cur["sbd_indicators"]) + ".", "evidence_refs": refs}
    elif ev and ev.get("stars", 0) >= 5000:
        criteria["c11_security_by_design_indicators"] = {"status": "partially_satisfied",
            "rationale": f"Widely deployed ({ev['stars']} stars); standard review and advisory exposure exist, but no explicit SBD documentation captured.", "evidence_refs": refs}
    else:
        criteria["c11_security_by_design_indicators"] = {"status": "pending_evidence",
            "rationale": "No security-by-design evidence captured for this component.",
            "evidence_refs": refs}

    criteria["c13_intended_use_alignment"] = {"status": "satisfied",
        "rationale": ("Component is used within its documented intended purpose per the curated product "
                      "use statement (see evidence/curated.json#product)."),
        "evidence_refs": ["evidence/curated.json#product", "sbom/immich-top-level.cdx.json#" + comp["purl"]]}

    return criteria


# --------------------------------------------------------------------------
# Overall tier (deterministic, given statuses)
# --------------------------------------------------------------------------

def overall_tier(criteria: dict) -> tuple[str, list[str]]:
    statuses = {k: v["status"] for k, v in criteria.items()}
    maintenance_not = any(statuses[k] == "not_satisfied"
                           for k in ("c09_recent_maintenance_activity", "c12_regular_patch_publication"))
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
               if s in ("not_satisfied", "pending_evidence") and k != "c01_ce_marking_and_eu_doc"]
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
    bundles = load(EVIDENCE_DIR / "llm_analysis.json")

    key = f"{comp['ecosystem']}/{comp['name']}"
    ev = evidence.get(key)
    maint = maintainers.get(key)
    cur = curated.get(key)
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
    for name in ("evidence", "maintainers", "curated", "llm_analysis"):
        digest.update(json.dumps(load(EVIDENCE_DIR / f"{name}.json"), sort_keys=True).encode())

    refs = evidence_refs(comp, ev, maint, cur)

    bundle = bundles.get(key)
    # api model annotation: ("llm", model_name, sub_note)
    if bundle:
        criteria = build_llm_criteria((bundle, {c: bundle["statuses"][c] for c in CRITERION_ORDER}), comp, refs)
        analyzer = {"kind": "llm",
                    "model": "mistral-llm-assistant (authored bundle, vibe session 2026-11-12)"}
    else:
        api = call_mistral_api(prompt_for(comp, ev, maint, cur))
        if api:
            parsed, statuses, model = api
            criteria = build_llm_criteria((parsed, statuses), comp, refs)
            analyzer = {"kind": "llm", "model": model}
        else:
            criteria = rule_criteria(comp, ev, maint, cur, refs)
            analyzer = {"kind": "rules"}

    # The input digest + linter make hand-editing documents detectable.
    tier, reasons = overall_tier(criteria)

    doc = {
        "schema_version": 1,
        "component": component_record,
        "assessed_at": ASSESSMENT_DATE + "T00:00:00Z",
        "analyzer": analyzer,
        "harness": {
            "subagent_pid": os.getpid(),
            "deterministic": True,
            "input_digest": digest.hexdigest(),
        },
        "criteria": criteria,
        "overall": {
            "risk_tier": tier,
            "requires_followup": tier in ("moderate", "high") or any(
                v["status"] == "not_satisfied" for v in criteria.values()),
            "followup_reasons": reasons,
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fname = comp["purl"].replace("/", "%2F").replace(":", "%3A")
    (OUT_DIR / f"{fname}.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")

    print(f"{comp['purl']}: analyzer={analyzer['kind']} tier={tier} followup={doc['overall']['requires_followup']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
