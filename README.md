<div align="center">

# SCOUT (AIEdge)

### Firmware-to-Exploit Evidence Engine

**From firmware blob to verified exploit chain — deterministic evidence at every step.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-34_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()

[English (this file)](README.md) | [한국어](README.ko.md)

</div>

---

## What is SCOUT?

SCOUT is a deterministic firmware analysis engine that transforms raw firmware blobs into hash-anchored exploit evidence chains. It runs a 34-stage sequential pipeline — from unpacking through vulnerability discovery to exploit verification — producing traceable, reproducible artifacts at every step. LLM judgment is deliberately separated into an orchestrator layer (Terminator), keeping the core evidence chain deterministic.

---

## Key Features

| | Feature | Description |
|---|---------|-------------|
| 📦 | **SBOM & CVE** | CycloneDX 1.6 SBOM generation + NVD API 2.0 CVE scanning with reachability analysis |
| 🔍 | **Binary Analysis** | ELF hardening audit (NX/PIE/RELRO/Canary) + optional Ghidra headless decompilation |
| 🎯 | **Attack Surface** | Source-to-sink tracing, IPC detection (5 types), credential auto-mapping |
| 🛡️ | **Security Assessment** | X.509 certificate scanning, boot service auditing, filesystem permission checks |
| 🧪 | **Fuzzing** | AFL++ pipeline with binary scoring, harness generation, crash triage |
| 🐛 | **Emulation** | 3-tier (FirmAE / QEMU user-mode / rootfs inspection) + GDB remote debugging |
| 🤖 | **MCP Server** | 12 tools exposed via Model Context Protocol for Claude Code/Desktop integration |
| 🧠 | **LLM Drivers** | Codex CLI + Claude API + Ollama — with cost tracking and budget limits |
| 📊 | **Web Viewer** | Glassmorphism dashboard with KPI bar, IPC map, risk heatmap, graph visualization |
| 🔗 | **Evidence Chain** | Hash-anchored artifacts, confidence caps, exploit tiering, verified chain gating |
| 📋 | **Executive Reports** | Auto-generated Markdown reports with top risks, SBOM/CVE tables, attack surface |
| 🔄 | **Firmware Diff** | Compare two analysis runs — filesystem, hardening, and config security changes |

---

## Quick Start

```bash
# Basic analysis (deterministic, no LLM)
./scout analyze firmware.bin --ack-authorization --no-llm --case-id my-test

# Pre-extracted rootfs (bypasses weak unpacking)
./scout analyze firmware.img --ack-authorization --no-llm --case-id my-test \
  --rootfs /path/to/extracted/rootfs

# Full exploit profile (lab environment only)
./scout analyze firmware.bin --ack-authorization --case-id my-test \
  --profile exploit --exploit-flag lab --exploit-scope lab-only \
  --exploit-attestation authorized

# MCP server for AI agents
./scout mcp --project-id aiedge-runs/<run_id>

# Web viewer
./scout serve aiedge-runs/<run_id> --port 8080
```

---

## Pipeline (34 Stages)

```
Firmware ─► Unpack ─► Profile ─► Inventory ─► [Ghidra] ─► SBOM ─► CVE Scan
    ─► Reachability ─► Security Assessment ─► Endpoints ─► Surfaces ─► Graph
    ─► Attack Surface ─► Findings ─► LLM Triage ─► LLM Synthesis
    ─► Emulation (3-tier) ─► [Fuzzing] ─► Exploit Chain ─► PoC ─► Verification
```

Stages in `[brackets]` require optional external tools (Ghidra, AFL++/Docker).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      SCOUT (Evidence Engine)                     │
│                                                                  │
│  Firmware ──► Unpack ──► Profile ──► Inventory ──► SBOM ──► CVE │
│                                       (+ hardening)  (NVD 2.0)  │
│                                                          │      │
│  ──► Security Assessment ──► Surfaces ──► Reachability ──► Find │
│      (cert/init/fs-perm)                 (BFS graph)            │
│                                                                  │
│  ──► [Ghidra] ──► LLM Triage ──► LLM Synthesis                 │
│  ──► Emulation ──► [Fuzzing] ──► Exploit ──► PoC ──► Verify     │
│                                                                  │
│  34 stages · stage.json manifests · SHA-256 hashed artifacts    │
├──────────────────────────────────────────────────────────────────┤
│                   Handoff (firmware_handoff.json)                 │
├──────────────────────────────────────────────────────────────────┤
│                    Terminator (Orchestrator)                      │
│  Tribunal ──► Validator ──► Exploit Dev ──► Verified Chain       │
│  (LLM judge)  (emulation)   (lab-gated)    (dynamic evidence)   │
└──────────────────────────────────────────────────────────────────┘
```

| Layer | Role | Deterministic? |
|:------|:-----|:--------------:|
| **SCOUT** | Evidence production (extraction, profiling, inventory, surfaces, findings) | Yes |
| **Handoff** | JSON contract between engine and orchestrator | Yes |
| **Terminator** | LLM tribunal, dynamic validation, exploit development, report promotion | No (auditable) |

---

## Exploit Promotion Policy

**Iron rule: no Confirmed without dynamic evidence.**

| Level | Requirements | Placement |
|:------|:-------------|:----------|
| `dismissed` | Critic rebuttal strong or confidence < 0.5 | Appendix only |
| `candidate` | Confidence 0.5-0.8, evidence exists but chain incomplete | Report (flagged) |
| `high_confidence_static` | Confidence >= 0.8, strong static evidence, no dynamic | Report (highlighted) |
| `confirmed` | Confidence >= 0.8 AND >= 1 dynamic verification artifact | Report (top) |
| `verified_chain` | Confirmed AND PoC reproduced 3x in sandbox, complete chain | Exploit report |

---

<details>
<summary><strong>CLI Reference</strong></summary>

| Command | Description |
|---------|-------------|
| `./scout analyze <firmware>` | Full firmware analysis pipeline |
| `./scout analyze-8mb <firmware>` | Truncated 8MB canonical track |
| `./scout stages <run_dir>` | Rerun specific stages on existing run |
| `./scout diff <old_run> <new_run>` | Compare two analysis runs |
| `./scout mcp --project-id <id>` | Start MCP stdio server |
| `./scout serve <run_dir>` | Launch web report viewer |
| `./scout tui <run_dir>` | Terminal UI dashboard |
| `./scout ti` | TUI interactive mode (latest run) |
| `./scout tw <run_dir> -t 2` | TUI watch mode (auto-refresh) |
| `./scout corpus-validate <run_dir>` | Validate corpus manifest |
| `./scout quality-metrics <run_dir>` | Compute quality metrics |
| `./scout quality-gate <run_dir>` | Check quality thresholds |
| `./scout release-quality-gate <run_dir>` | Unified release gate |

**Exit codes:** `0` success, `10` partial, `20` fatal, `30` policy violation

</details>

<details>
<summary><strong>Environment Variables</strong></summary>

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_LLM_DRIVER` | `codex` | LLM provider: `codex` / `claude` / `ollama` |
| `ANTHROPIC_API_KEY` | — | API key for Claude driver |
| `AIEDGE_OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `AIEDGE_LLM_BUDGET_USD` | — | LLM cost budget limit |
| `AIEDGE_PRIV_RUNNER` | — | Privileged command prefix for dynamic stages |
| `AIEDGE_FEEDBACK_DIR` | `aiedge-feedback` | Terminator feedback directory |

### SBOM & CVE

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_NVD_API_KEY` | — | NVD API key (optional, improves rate limits) |
| `AIEDGE_NVD_CACHE_DIR` | `aiedge-nvd-cache` | Cross-run NVD response cache |
| `AIEDGE_SBOM_MAX_COMPONENTS` | `500` | Maximum SBOM components |
| `AIEDGE_CVE_SCAN_MAX_COMPONENTS` | `50` | Maximum components to CVE-scan |
| `AIEDGE_CVE_SCAN_TIMEOUT_S` | `30` | Per-request NVD API timeout |

### LLM Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_LLM_CHAIN_TIMEOUT_S` | `180` | LLM synthesis timeout |
| `AIEDGE_LLM_CHAIN_MAX_ATTEMPTS` | `5` | LLM synthesis max retries |
| `AIEDGE_AUTOPOC_LLM_TIMEOUT_S` | `180` | Auto-PoC LLM timeout |
| `AIEDGE_AUTOPOC_LLM_MAX_ATTEMPTS` | `4` | Auto-PoC max retries |

### Ghidra

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_GHIDRA_HOME` | — | Ghidra installation path |
| `AIEDGE_GHIDRA_MAX_BINARIES` | `20` | Max binaries to analyze |
| `AIEDGE_GHIDRA_TIMEOUT_S` | `300` | Per-binary analysis timeout |

### Fuzzing (AFL++)

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_AFLPP_IMAGE` | `aflplusplus/aflplusplus` | AFL++ Docker image |
| `AIEDGE_FUZZ_BUDGET_S` | `3600` | Fuzzing time budget (seconds) |
| `AIEDGE_FUZZ_MAX_TARGETS` | `5` | Max fuzzing target binaries |

### Emulation

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_EMULATION_IMAGE` | `scout-emulation:latest` | Tier 1 Docker image |
| `AIEDGE_FIRMAE_ROOT` | `/opt/FirmAE` | FirmAE installation path |
| `AIEDGE_QEMU_GDB_PORT` | `1234` | QEMU GDB remote port |

### MCP & Port Scanning

| Variable | Default | Description |
|----------|---------|-------------|
| `AIEDGE_MCP_MAX_OUTPUT_KB` | `512` | MCP response max size |
| `AIEDGE_PORTSCAN_TOP_K` | `1000` | Top-K ports to scan |
| `AIEDGE_PORTSCAN_WORKERS` | `128` | Concurrent scan workers |
| `AIEDGE_PORTSCAN_BUDGET_S` | `120` | Port scan time budget |

</details>

<details>
<summary><strong>Run Directory Structure</strong></summary>

```
aiedge-runs/<run_id>/
├── manifest.json
├── firmware_handoff.json
├── input/firmware.bin
├── stages/
│   ├── tooling/
│   ├── extraction/
│   ├── firmware_profile/
│   ├── inventory/
│   │   └── binary_analysis.json     # per-binary hardening data
│   ├── sbom/
│   │   └── sbom.json                # CycloneDX 1.6 + CPE index
│   ├── cve_scan/
│   │   └── cve_scan.json            # NVD API CVE matches
│   ├── reachability/
│   │   └── reachability.json        # BFS reachability classification
│   ├── surfaces/
│   │   └── source_sink_graph.json
│   ├── ghidra_analysis/             # optional
│   ├── findings/
│   │   ├── pattern_scan.json
│   │   ├── credential_mapping.json
│   │   └── chains.json
│   ├── fuzzing/                     # optional
│   │   └── fuzz_results.json
│   └── graph/
│       └── communication_graph.json
└── report/
    ├── report.json
    ├── analyst_digest.json
    └── executive_report.md
```

</details>

<details>
<summary><strong>Verification Scripts</strong></summary>

```bash
# Evidence chain integrity
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# Report schema compliance
python3 scripts/verify_aiedge_final_report.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

# Security invariants
python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_exploit_meaningfulness.py --run-dir aiedge-runs/<run_id>

# Quality gates
./scout quality-gate aiedge-runs/<run_id>
./scout release-quality-gate aiedge-runs/<run_id>
```

</details>

---

## Documentation

| Document | Purpose |
|:---------|:--------|
| [Blueprint](docs/blueprint.md) | Full pipeline architecture and design rationale |
| [Status](docs/status.md) | Current implementation status |
| [Artifact Schema](docs/aiedge_firmware_artifacts_v1.md) | Profiling + inventory artifact contracts |
| [Adapter Contract](docs/aiedge_adapter_contract.md) | Terminator-SCOUT handoff protocol |
| [Report Contract](docs/aiedge_report_contract.md) | Report structure and governance rules |
| [Analyst Digest](docs/analyst_digest_contract.md) | Digest schema and verdict semantics |
| [Verified Chain](docs/verified_chain_contract.md) | Evidence requirements for verified chains |
| [Duplicate Gate](docs/aiedge_duplicate_gate_contract.md) | Cross-run duplicate suppression rules |
| [Runbook](docs/runbook.md) | Operator flow for digest-first review |

---

## Security & Ethics

> **Authorized environments only.**

SCOUT is intended for use in controlled environments with proper authorization:

- **Contracted security audits** — vendor-coordinated firmware assessments
- **Vulnerability research** — responsible disclosure with coordinated timelines
- **CTF and training** — designated targets in lab environments

Dynamic validation runs in network-isolated sandbox containers. PoC execution requires explicit `--ack-authorization` and lab attestation flags. No weaponized payloads are included.

---

## License

MIT
