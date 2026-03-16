# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SCOUT (AIEdge) is a deterministic firmware-to-exploit evidence engine. It takes firmware blobs as input and produces hash-anchored evidence artifacts through a 27-stage sequential pipeline — from unpacking through vulnerability discovery to exploit chain verification. SCOUT is the evidence-production layer; a separate orchestrator (Terminator) applies LLM judgment and dynamic validation on top via `firmware_handoff.json`.

**Key constraints:** Pure Python 3.10+ with zero pip dependencies (stdlib only). External tools (binwalk, QEMU, FirmAE, docker) are runtime-optional.

## Build, Test, and Run Commands

```bash
# CLI help
./scout --help

# Deterministic analysis (no LLM)
./scout analyze firmware.bin --ack-authorization --no-llm --case-id <id>

# With specific stages
./scout analyze firmware.bin --ack-authorization --no-llm --case-id <id> \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory

# Pre-extracted rootfs bypass (when extraction is weak)
./scout analyze firmware.img --ack-authorization --no-llm --case-id <id> \
  --rootfs /path/to/extracted/rootfs

# Rerun specific stages on existing run
./scout stages aiedge-runs/<run_id> --no-llm --stages inventory

# Full exploit profile (requires authorization flags)
./scout analyze firmware.bin --ack-authorization --case-id <id> \
  --profile exploit --exploit-flag lab --exploit-attestation authorized --exploit-scope lab-only

# Run tests
pytest -q                                        # full suite
pytest -q tests/test_inventory.py                # single module
pytest -q tests/test_inventory.py::test_func     # single test

# Type checking (pyright configured via pyrightconfig.json)
pyright src/

# Verification scripts
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>
scripts/release_gate.sh --run-dir aiedge-runs/<run_id>   # unified release gate

# TUI dashboard (./scout provides shortcut aliases)
./scout tui aiedge-runs/<run_id> --interactive   # interactive mode
./scout tw aiedge-runs/<run_id> -t 2             # live-refresh (watch)
./scout ti                                       # alias: tui -i (interactive, latest run)
./scout to                                       # alias: tui -m once
./scout t                                        # alias: tui (latest run)

# Serve report viewer
./scout serve aiedge-runs/<run_id>
```

## Architecture

### Stage Pipeline

Stages execute sequentially via `run_stages()` in `src/aiedge/stage.py`. Each stage implements the `Stage` Protocol (structural typing, not ABC):
- Property `name: str`
- Method `run(ctx: StageContext) -> StageOutcome`

Stages are registered as factory functions in `src/aiedge/stage_registry.py` (`_STAGE_FACTORIES` dict). Stage factories are instantiated by `run.py` which manages run directories, manifests, and report finalization.

**Execution order:** tooling → extraction → structure → carving → firmware_profile → inventory → endpoints → surfaces → web_ui → graph → attack_surface → functional_spec → threat_model → **findings** → **llm_triage** → llm_synthesis → attribution → dynamic_validation → emulation → exploit_gate → exploit_chain → exploit_autopoc → poc_validation → exploit_policy (plus OTA-specific stages: ota, ota_payload, ota_fs, ota_roots, ota_boottriage, firmware_lineage)

### Inter-Stage Communication

Stages have **no in-memory coupling**. Each stage reads JSON artifacts from predecessor directories in `run_dir/stages/<predecessor>/` and writes to `run_dir/stages/<own_name>/`. The `stage.json` file in each stage directory records status, timing, artifact paths with SHA-256 hashes, and limitations.

### Key Abstractions

| Type | Location | Purpose |
|------|----------|---------|
| `Stage` Protocol | `stage.py:59-63` | Interface all stages implement |
| `StageContext` | `stage.py:26-29` | Frozen dataclass: `run_dir`, `logs_dir`, `report_dir` |
| `StageOutcome` | `stage.py` | Result: `status` (ok/partial/failed/skipped), `details`, `limitations` |
| `StageFactory` | `stage_registry.py:35` | Callable creating Stage from run info |
| `RunReport` | `stage.py` | Aggregated result of all stages |

### Evidence & Governance Layers

- **Confidence caps** (`confidence_caps.py`): Static-only findings capped at 0.60 confidence
- **Exploit tiering** (`exploit_tiering.py`): suspected → strong_static → dynamic_repro → exploitability_assessed
- **Determinism** (`determinism.py`): Canonical JSON bundles ensure reproducible runs
- **Quality gates** (`quality_policy.py`, `quality_metrics.py`): Threshold checks and corpus-based evaluation
- **Schema validation** (`schema.py`): Report validation, version tracking, verdict semantics

### Findings Stage — Special Pattern

The `findings` stage is **not** registered in `_STAGE_FACTORIES`. It runs as an integrated step via `run_findings(ctx)` called directly from `run.py` during full `analyze`/`analyze-8mb` execution, after all registered stages complete. It cannot be invoked standalone via `--stages findings`. Its output goes to `run_dir/stages/findings/*.json`.

### CLI Entry Point

All CLI subcommands defined in `_build_parser()` (~line 3367 of `__main__.py`) and dispatched in `main()` (~line 3905). The TUI rendering logic (~2500 lines) is also in `__main__.py`. The `./scout` shell wrapper adds short aliases (`t`, `ti`, `tw`, `to`) and sets up `PYTHONPATH`.

### Path Safety

`_assert_under_dir()` is used across all 23+ stage modules to enforce that artifact paths stay within the run directory. This is a critical security invariant — every file write in a stage must pass this check.

## Adding a New Pipeline Stage

1. Create `src/aiedge/your_stage.py` implementing the `Stage` protocol
2. Add a factory function in `stage_registry.py` and register in `_STAGE_FACTORIES`
3. Use `_assert_under_dir(ctx.run_dir, path)` for all file writes
4. Stage output goes to `run_dir/stages/your_stage/stage.json` + artifacts
5. Add tests in `tests/test_your_stage.py`

Recent example: `llm_triage` stage (`src/aiedge/llm_triage.py`) is registered in `_STAGE_FACTORIES` and runs between `findings` and `llm_synthesis`. It reads findings artifacts, applies LLM-assisted prioritization with security context, and writes `stages/llm_triage/triage.json`.

## Critical Coupling Points

- **`stage.py`** Protocol/dataclass changes affect all 27 stages
- **`schema.py`** validation changes affect report generation, quality gates, and all verification scripts
- **`run.py`** report finalization changes affect all verification scripts and handoff generation
- Individual stage modules are well-isolated and safe to modify independently

## Environment Variables

Key configuration prefixes (no config files, environment-variable-driven):
- `AIEDGE_PORTSCAN_*` — port scanning parameters (TOP_K, START, END, WORKERS, BUDGET_S, FULL_RANGE)
- `AIEDGE_LLM_CHAIN_*` — LLM synthesis timeouts and retry limits
- `AIEDGE_AUTOPOC_LLM_*` — Auto-PoC LLM parameters
- `AIEDGE_PRIV_RUNNER` — privileged command prefix for dynamic validation
- `AIEDGE_ATTACK_SURFACE_MAX_*` — attack surface scan limits
- `AIEDGE_BINARY_STRINGS_BUDGET` — binary strings analysis budget
- `AIEDGE_DUPLICATE_*` — cross-run duplicate suppression
- `AIEDGE_TUI_ASCII` — force ASCII-only TUI rendering
- `AIEDGE_RUNS_DIRS` — custom run output directories
- `AIEDGE_LLM_DRIVER` — LLM provider selection (default: codex)
- `AIEDGE_EMULATION_IMAGE` — Docker image for Tier 1 FirmAE emulation (default: scout-emulation:latest)
- `AIEDGE_FIRMAE_ROOT` — FirmAE installation path (default: /opt/FirmAE)
- `AIEDGE_FEEDBACK_DIR` — Terminator feedback directory for bidirectional handoff

## Design Invariants

- **All artifact paths must be run-dir-relative.** Absolute paths in outputs are bugs. `_assert_under_dir()` enforces path traversal prevention.
- **Stages fail open, governance fails closed.** Individual stages return `partial` with whatever they could produce. Promotion gates (quality gate, release gate, verified chain) reject incomplete evidence.
- **No finding without evidence.** Every finding requires file path, offset, hash, and rationale.
- **`--ack-authorization` is mandatory** for every analysis. Exploit profile requires additional attestation flags.
- **Generated runtime artifacts** (`aiedge-runs/`, `aiedge-inputs/`, `aiedge-8mb-runs/`) are local outputs — never commit them.

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/blueprint.md` | Full pipeline architecture and design rationale |
| `docs/status.md` | Current implementation status |
| `docs/aiedge_firmware_artifacts_v1.md` | Schema contracts for profiling + inventory |
| `docs/aiedge_adapter_contract.md` | Terminator↔SCOUT handoff protocol |
| `docs/aiedge_report_contract.md` | Report structure and governance rules |
| `docs/analyst_digest_contract.md` | Analyst digest schema and verdict semantics |
| `docs/runbook.md` | Operator flow for digest-first review |
