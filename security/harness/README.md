# CRA Due-Diligence Assessment Harness

Deterministic harness that assesses every top-level dependency of the SBOM
(`security/sbom/immich-top-level.cdx.json`, 333 components) against the
original CRA due-diligence criteria (CE marking/DoC, known vulnerabilities,
patch availability, disclosure process, risk assessment, additional testing,
technical verification, support period, maintenance activity, stewardship,
security-by-design, patch cadence, intended use).

## Design

- **One dedicated sub-agent process per dependency.** The driver
  (`run_harness.sh`) iterates the SBOM and spawns
  `assess_component.py <purl>` once per component. Each sub-agent run is
  fully isolated: single component in, single JSON document out.
- **LLM analysis layer, not a rule engine.** Each sub-agent's criterion
  judgments come from an LLM: (1) the LLM-authored analysis bundle in
  `evidence/llm_analysis.json` (judgments written component-by-component by
  the Mistral assistant on 2026-11-12 from the evidence), (2) a live
  Mistral API call in JSON mode when `MISTRAL_API_KEY` is set (for
  components without a bundle), and (3) a deterministic rules fallback so the
  harness never fails silently. The `analyzer` field in every document
  records which layer produced the judgments (`llm` or `rules`), and the
  linter enforces the field. Rationales, per-criterion notes and risk
  reasoning are LLM text; only the aggregation into a risk tier is
  deterministic (documented formula in `assess_component.py`), keeping the
  harness reproducible.
- **Output contract defined beforehand.** Every sub-agent must emit a
  document conforming to `assessment.schema.json` (JSON Schema draft
  2020-12): fixed criteria keys `c01`–`c13`, status enums
  (`satisfied` / `partially_satisfied` / `not_satisfied` / `not_applicable` /
  `pending_evidence`), component identity fields, and an overall risk tier
  (`low` / `low-moderate` / `moderate` / `high` / `not_assessed`).
- **Linter gate.** `lint_assessments.py` validates every document in
  `assessments/` against the schema **plus** structural invariants a schema
  cannot express: purl/name/version/ecosystem/scope/workspaces must match the
  SBOM entry, no duplicate purls, recomputable `input_digest`, and
  `pending_evidence` criteria must cite evidence refs. Non-zero exit gates CI.
- **Determinism.** Each sub-agent's judgments are pure functions of
  (SBOM component record, `evidence/*.json`). Two runs on unchanged inputs
  produce identical documents (only the recorded PID differs). `input_digest`
  (SHA-256 over canonical inputs) proves which inputs produced a document;
  the linter recomputes it.

## Layout

```
assessment.schema.json   output contract (defined before any sub-agent runs)
run_harness.sh           driver: one sub-agent process per SBOM component, then lint
assess_component.py      sub-agent worker (single component -> strict JSON)
lint_assessments.py      schema + invariant linter (CI gate)
evidence/
  evidence.json          machine-verified upstream activity (GitHub API, crates.io, repo pages)
  maintainers.json       curated stewardship map (class: foundation/corporate/community/individual)
  curated.json           curated CVE history, SBD indicators, product-level judgments
  llm_analysis.json      LLM-authored due-diligence judgments (per-criterion statuses + rationales)
assessments/             one validated JSON document per component
```

## Usage

```
./run_harness.sh                    # assess all components, then lint
./run_harness.sh --scope required   # runtime dependencies only (SBOM scope filter)
./run_harness.sh --lint-only        # re-validate existing documents
```

## Current result snapshot (2026-11-12)

- 333 documents, all lint-clean: 89 LLM-analyzed (`analyzer.kind = "llm"`),
  244 rules-fallback (`analyzer.kind = "rules"` — no evidence, judged
  `not_assessed` pending collection).
- LLM-analyzed set: 2 high (`dom-to-image`, `qrcode` — stale upstream),
  6 low (express, pydantic, nestjs core, socket.io(-client), react…), 81
  low-moderate (stewardship known; keep evidence current).
- Every document lists `followup_reasons`; high-tier documents carry
  explicit replacement recommendations in the LLM rationales.

## Adding evidence

Evidence is data, not code: to turn a `not_assessed` component into a full
assessment, add a record keyed `<ecosystem>/<name>` to `evidence/evidence.json`
(push date, security policy flag, license, stars — as accepted from the GitHub
API), optionally a stewardship class in `maintainers.json` and CVE history in
`curated.json`, then re-run the harness. Re-run `--lint-only` after any manual
edit of a document to detect tampering (digest mismatch).
