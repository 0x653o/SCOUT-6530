<div align="center">

# SCOUT (AIEdge)

### Firmware-to-Exploit Evidence Engine

**펌웨어 바이너리에서 검증된 익스플로잇 체인까지 — 모든 단계에서 결정론적 증거 생성.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stages](https://img.shields.io/badge/Pipeline-34_Stages-blueviolet?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()

[English](README.md) | [한국어 (이 파일)](README.ko.md)

</div>

---

## SCOUT란?

SCOUT는 펌웨어 바이너리를 해시 기반 익스플로잇 증거 체인으로 변환하는 결정론적 분석 엔진입니다. 34단계 순차 파이프라인을 통해 압축 해제부터 취약점 발견, 익스플로잇 검증까지 추적 가능하고 재현 가능한 아티팩트를 생성합니다. LLM 판단은 의도적으로 오케스트레이터 레이어(Terminator)에 분리하여 핵심 증거 체인의 결정론성을 보장합니다.

---

## 주요 기능

| | 기능 | 설명 |
|---|------|------|
| 📦 | **SBOM & CVE** | CycloneDX 1.6 SBOM 생성 + NVD API 2.0 CVE 스캔 및 도달성 분석 |
| 🔍 | **바이너리 분석** | ELF 하드닝 감사 (NX/PIE/RELRO/Canary) + 선택적 Ghidra 헤드리스 디컴파일 |
| 🎯 | **공격면 분석** | Source-to-sink 추적, IPC 감지 (5종), 자격증명 자동 매핑 |
| 🛡️ | **보안 평가** | X.509 인증서 스캔, 부트 서비스 감사, 파일시스템 권한 검사 |
| 🧪 | **퍼징** | AFL++ 파이프라인 — 바이너리 스코어링, 하네스 생성, 크래시 트리아지 |
| 🐛 | **에뮬레이션** | 3-Tier (FirmAE / QEMU user-mode / rootfs 검사) + GDB 원격 디버깅 |
| 🤖 | **MCP 서버** | Model Context Protocol로 12개 도구 노출 — Claude Code/Desktop 연동 |
| 🧠 | **LLM 드라이버** | Codex CLI + Claude API + Ollama — 비용 추적 및 예산 제한 |
| 📊 | **웹 뷰어** | 글래스모피즘 대시보드 — KPI 바, IPC 맵, 리스크 히트맵, 그래프 시각화 |
| 🔗 | **증거 체인** | 해시 기반 아티팩트, 신뢰도 상한, 익스플로잇 티어링, verified chain 게이팅 |
| 📋 | **임원 보고서** | 상위 위험, SBOM/CVE 테이블, 공격면 포함 Markdown 보고서 자동 생성 |
| 🔄 | **펌웨어 비교** | 두 분석 런 비교 — 파일시스템, 하드닝, 설정 보안 변경사항 |

---

## 빠른 시작

```bash
# 기본 분석 (결정론적, LLM 미사용)
./scout analyze firmware.bin --ack-authorization --no-llm --case-id my-test

# 사전 추출 rootfs (약한 압축 해제 우회)
./scout analyze firmware.img --ack-authorization --no-llm --case-id my-test \
  --rootfs /path/to/extracted/rootfs

# 전체 익스플로잇 프로필 (실험실 환경 전용)
./scout analyze firmware.bin --ack-authorization --case-id my-test \
  --profile exploit --exploit-flag lab --exploit-scope lab-only \
  --exploit-attestation authorized

# AI 에이전트용 MCP 서버
./scout mcp --project-id aiedge-runs/<run_id>

# 웹 뷰어
./scout serve aiedge-runs/<run_id> --port 8080
```

---

## 파이프라인 (34단계)

```
Firmware ─► Unpack ─► Profile ─► Inventory ─► [Ghidra] ─► SBOM ─► CVE Scan
    ─► Reachability ─► Security Assessment ─► Endpoints ─► Surfaces ─► Graph
    ─► Attack Surface ─► Findings ─► LLM Triage ─► LLM Synthesis
    ─► Emulation (3-tier) ─► [Fuzzing] ─► Exploit Chain ─► PoC ─► Verification
```

`[괄호]` 안의 스테이지는 선택적 외부 도구(Ghidra, AFL++/Docker)가 필요합니다.

---

## 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│                      SCOUT (증거 엔진)                           │
│                                                                  │
│  Firmware ──► Unpack ──► Profile ──► Inventory ──► SBOM ──► CVE │
│                                       (+ 하드닝)    (NVD 2.0)   │
│                                                          │      │
│  ──► 보안 평가 ──► Surfaces ──► 도달성 분석 ──► Findings        │
│      (cert/init/fs-perm)          (BFS 그래프)                  │
│                                                                  │
│  ──► [Ghidra] ──► LLM 트리아지 ──► LLM 합성                    │
│  ──► 에뮬레이션 ──► [퍼징] ──► 익스플로잇 ──► PoC ──► 검증     │
│                                                                  │
│  34단계 · stage.json 매니페스트 · SHA-256 해시 아티팩트         │
├──────────────────────────────────────────────────────────────────┤
│                   Handoff (firmware_handoff.json)                 │
├──────────────────────────────────────────────────────────────────┤
│                    Terminator (오케스트레이터)                     │
│  Tribunal ──► Validator ──► Exploit Dev ──► Verified Chain       │
│  (LLM 심판)   (에뮬레이션)   (lab-gated)    (동적 증거)         │
└──────────────────────────────────────────────────────────────────┘
```

| 레이어 | 역할 | 결정론적? |
|:-------|:-----|:---------:|
| **SCOUT** | 증거 생성 (추출, 프로파일링, 인벤토리, 공격면, findings) | 예 |
| **Handoff** | 엔진과 오케스트레이터 간 JSON 계약 | 예 |
| **Terminator** | LLM 심판, 동적 검증, 익스플로잇 개발, 리포트 승격 | 아니오 (감사 가능) |

---

## 익스플로잇 승격 정책

**철칙: 동적 증거 없이는 Confirmed 없음.**

| 레벨 | 요구 사항 | 표시 위치 |
|:-----|:----------|:----------|
| `dismissed` | Critic 반박 강함 또는 신뢰도 < 0.5 | 부록만 |
| `candidate` | 신뢰도 0.5-0.8, 증거 존재하나 체인 불완전 | 리포트 (플래그) |
| `high_confidence_static` | 신뢰도 >= 0.8, 정적 증거 강함, 동적 검증 없음 | 리포트 (강조) |
| `confirmed` | 신뢰도 >= 0.8 AND 동적 검증 아티팩트 >= 1개 | 리포트 (상단) |
| `verified_chain` | Confirmed AND 샌드박스에서 PoC 3회 재현, 완전한 체인 | 익스플로잇 리포트 |

---

<details>
<summary><strong>CLI 레퍼런스</strong></summary>

| 명령어 | 설명 |
|--------|------|
| `./scout analyze <firmware>` | 전체 펌웨어 분석 파이프라인 |
| `./scout analyze-8mb <firmware>` | 8MB 트런케이션 트랙 |
| `./scout stages <run_dir>` | 기존 런에서 특정 스테이지 재실행 |
| `./scout diff <old_run> <new_run>` | 두 분석 런 비교 |
| `./scout mcp --project-id <id>` | MCP stdio 서버 시작 |
| `./scout serve <run_dir>` | 웹 리포트 뷰어 실행 |
| `./scout tui <run_dir>` | 터미널 UI 대시보드 |
| `./scout ti` | TUI 인터랙티브 모드 (최근 런) |
| `./scout tw <run_dir> -t 2` | TUI watch 모드 (자동 갱신) |
| `./scout corpus-validate <run_dir>` | 코퍼스 매니페스트 검증 |
| `./scout quality-metrics <run_dir>` | 품질 메트릭 계산 |
| `./scout quality-gate <run_dir>` | 품질 임계값 확인 |
| `./scout release-quality-gate <run_dir>` | 통합 릴리스 게이트 |

**종료 코드:** `0` 성공, `10` 부분 성공, `20` 치명적 오류, `30` 정책 위반

</details>

<details>
<summary><strong>환경 변수</strong></summary>

### 코어

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_LLM_DRIVER` | `codex` | LLM 제공자: `codex` / `claude` / `ollama` |
| `ANTHROPIC_API_KEY` | — | Claude 드라이버 API 키 |
| `AIEDGE_OLLAMA_URL` | `http://localhost:11434` | Ollama 서버 URL |
| `AIEDGE_LLM_BUDGET_USD` | — | LLM 비용 예산 한도 |
| `AIEDGE_PRIV_RUNNER` | — | 동적 단계용 권한 명령 접두사 |
| `AIEDGE_FEEDBACK_DIR` | `aiedge-feedback` | Terminator 피드백 디렉토리 |

### SBOM & CVE

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_NVD_API_KEY` | — | NVD API 키 (선택, 속도 제한 완화) |
| `AIEDGE_NVD_CACHE_DIR` | `aiedge-nvd-cache` | 크로스런 NVD 응답 캐시 |
| `AIEDGE_SBOM_MAX_COMPONENTS` | `500` | 최대 SBOM 컴포넌트 수 |
| `AIEDGE_CVE_SCAN_MAX_COMPONENTS` | `50` | CVE 스캔 대상 최대 컴포넌트 수 |
| `AIEDGE_CVE_SCAN_TIMEOUT_S` | `30` | NVD API 요청당 타임아웃 |

### LLM 타임아웃

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_LLM_CHAIN_TIMEOUT_S` | `180` | LLM 합성 타임아웃 |
| `AIEDGE_LLM_CHAIN_MAX_ATTEMPTS` | `5` | LLM 합성 최대 재시도 |
| `AIEDGE_AUTOPOC_LLM_TIMEOUT_S` | `180` | Auto-PoC LLM 타임아웃 |
| `AIEDGE_AUTOPOC_LLM_MAX_ATTEMPTS` | `4` | Auto-PoC 최대 재시도 |

### Ghidra

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_GHIDRA_HOME` | — | Ghidra 설치 경로 |
| `AIEDGE_GHIDRA_MAX_BINARIES` | `20` | 분석 대상 최대 바이너리 수 |
| `AIEDGE_GHIDRA_TIMEOUT_S` | `300` | 바이너리당 분석 타임아웃 |

### 퍼징 (AFL++)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_AFLPP_IMAGE` | `aflplusplus/aflplusplus` | AFL++ Docker 이미지 |
| `AIEDGE_FUZZ_BUDGET_S` | `3600` | 퍼징 시간 예산 (초) |
| `AIEDGE_FUZZ_MAX_TARGETS` | `5` | 최대 퍼징 대상 바이너리 수 |

### 에뮬레이션

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_EMULATION_IMAGE` | `scout-emulation:latest` | Tier 1 Docker 이미지 |
| `AIEDGE_FIRMAE_ROOT` | `/opt/FirmAE` | FirmAE 설치 경로 |
| `AIEDGE_QEMU_GDB_PORT` | `1234` | QEMU GDB 원격 포트 |

### MCP & 포트 스캔

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AIEDGE_MCP_MAX_OUTPUT_KB` | `512` | MCP 응답 최대 크기 |
| `AIEDGE_PORTSCAN_TOP_K` | `1000` | 상위 K개 포트 스캔 |
| `AIEDGE_PORTSCAN_WORKERS` | `128` | 동시 스캔 워커 수 |
| `AIEDGE_PORTSCAN_BUDGET_S` | `120` | 포트 스캔 시간 예산 |

</details>

<details>
<summary><strong>실행 디렉토리 구조</strong></summary>

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
│   │   └── binary_analysis.json     # 바이너리별 하드닝 데이터
│   ├── sbom/
│   │   └── sbom.json                # CycloneDX 1.6 + CPE 인덱스
│   ├── cve_scan/
│   │   └── cve_scan.json            # NVD API CVE 매칭 결과
│   ├── reachability/
│   │   └── reachability.json        # BFS 도달성 분류
│   ├── surfaces/
│   │   └── source_sink_graph.json
│   ├── ghidra_analysis/             # 선택사항
│   ├── findings/
│   │   ├── pattern_scan.json
│   │   ├── credential_mapping.json
│   │   └── chains.json
│   ├── fuzzing/                     # 선택사항
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
<summary><strong>검증 스크립트</strong></summary>

```bash
# 증거 체인 무결성
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>

# 리포트 스키마 준수
python3 scripts/verify_aiedge_final_report.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

# 보안 불변 조건
python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_exploit_meaningfulness.py --run-dir aiedge-runs/<run_id>

# 품질 게이트
./scout quality-gate aiedge-runs/<run_id>
./scout release-quality-gate aiedge-runs/<run_id>
```

</details>

---

## 문서

| 문서 | 목적 |
|:-----|:-----|
| [Blueprint](docs/blueprint.md) | 전체 파이프라인 아키텍처 및 설계 근거 |
| [Status](docs/status.md) | 현재 구현 상태 |
| [아티팩트 스키마](docs/aiedge_firmware_artifacts_v1.md) | 프로파일링 + 인벤토리 아티팩트 계약 |
| [어댑터 계약](docs/aiedge_adapter_contract.md) | Terminator-SCOUT 핸드오프 프로토콜 |
| [리포트 계약](docs/aiedge_report_contract.md) | 리포트 구조 및 거버넌스 규칙 |
| [Analyst Digest](docs/analyst_digest_contract.md) | 다이제스트 스키마 및 판정 의미론 |
| [Verified Chain](docs/verified_chain_contract.md) | verified chain 증거 요구사항 |
| [Duplicate Gate](docs/aiedge_duplicate_gate_contract.md) | 크로스런 중복 억제 규칙 |
| [Runbook](docs/runbook.md) | digest-first 검토 운영 흐름 |

---

## 보안 및 윤리

> **승인된 환경에서만 사용하십시오.**

SCOUT는 적절한 승인 하에 통제된 환경에서 사용해야 합니다:

- **계약 기반 보안 감사** — 벤더 협의가 완료된 펌웨어 보안 평가
- **취약점 연구** — 협조적 공개 타임라인을 갖춘 책임 있는 공개
- **CTF 및 훈련** — 실험실 환경의 지정된 대상

동적 검증은 네트워크 격리된 샌드박스 컨테이너에서 실행됩니다. PoC 실행은 명시적인 `--ack-authorization`과 실험실 증명 플래그가 필요합니다. Weaponized payload는 포함되지 않습니다.

---

## 라이선스

MIT
