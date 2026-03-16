# SCOUT (AIEdge)

<div align="center">

### Firmware-to-Exploit Evidence Engine

**펌웨어 바이너리에서 검증 가능한 취약점 체인(Exploit Chain)까지**  
해시 기반 증거로 추적 가능한 단계형 분석 엔진

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## 한 줄 요약

SCOUT는 펌웨어 분석 결과를 "가능한 취약점 목록"에서 멈추지 않고,
`static 분석 증거 → 동적 검증 증거 → exploit PoC → verified_chain`까지의 **증거 체인**으로 연결하려고 설계된 도구입니다.

---

## 핵심 원칙

- **증거 우선( Evidence-first )**  
  모든 주장(탐지/후보/확인)은 run_dir의 파일 경로, 오프셋, 해시, 증거 파일로 추적 가능합니다.
- **결정론적 증거 생성 + 비결정론적 판단 분리**  
  정적 분석은 재현 가능하게 동작하고, LLM 판단은 별도 레이어(Orchestrator)에서 감사 로그와 함께 수행됩니다.
- **Fail-closed 거버넌스**  
  결과는 완전하지 않더라도 저장은 하되, **확인(confirmed/verified)** 판정은 게이트에서 엄격하게 제한합니다.
- **Full-Chain 또는 Nothing**  
  후보 제시에 그치지 않고, 취약점 후보 → 익스플로잇 원시 → PoC → 검증 가능한 체인으로 진행 상태를 명시합니다.

---

## 최근 동기화 포인트

- **바이너리 하드닝 분석** — 순수 Python ELF 파서로 NX, PIE, RELRO, Stack Canary, Stripped 상태를 바이너리별로 수집. `inventory/binary_analysis.json`에 `hardening_summary` 포함. findings 점수에 하드닝 기반 보정 적용 (fully hardened: x0.7, no protection: x1.15).
- **3-Tier 에뮬레이션** — Tier 1: FirmAE 시스템 에뮬레이션(Docker 컨테이너, sudo 불필요), Tier 2: QEMU user-mode 서비스 프로빙(lighttpd, busybox, dnsmasq, sshd 등), Tier 3: rootfs 검사(Alpine Docker fallback). `AIEDGE_EMULATION_IMAGE`, `AIEDGE_FIRMAE_ROOT` env var로 설정.
- **엔디안 인식 아키텍처 감지** — MIPS/ARM 빅/리틀엔디안 정확 구분: `mips_be`, `mips_le`, `arm_be`, `arm_le`.
- **LLM Provider 추상화** — `llm_driver.py`의 `LLMDriver` Protocol과 `CodexCLIDriver`. 3개 호출사이트(llm_synthesis, exploit_autopoc, llm_codex) 통합. `AIEDGE_LLM_DRIVER` env var로 provider 선택, `ModelTier` ("haiku"|"sonnet"|"opus") 지원.
- **취약점 유형별 PoC 템플릿** — `poc_templates.py` 레지스트리: `cmd_injection`, `path_traversal`, `auth_bypass`, `info_disclosure` 4종 + `tcp_banner` fallback. `poc_skeletons/` 디렉토리에 standalone 파일.
- **exploit_runner 실제 PCAP 캡처** — tcpdump 가용 시 실제 패킷 캡처 (기존 placeholder fallback 유지).
- **PoC 재현성 검증** — `poc_validation`에서 readback_hash 일관성 확인으로 재현성 보장.
- **LLM 보조 트리아지 스테이지** (`llm_triage`) — findings → llm_synthesis 사이에 실행. 모델 티어 자동 선택: <10 후보 → haiku, 10–50 → sonnet, >50 → opus. 하드닝/attack_surface 보안 컨텍스트 포함. `--no-llm`에서 graceful skip.
- **Terminator 양방향 피드백 루프** — `terminator_feedback.py`가 `firmware_handoff.json`에 `feedback_request` 섹션 추가. Terminator 판정(confirmed boost, false_positive suppress)이 `duplicate_gate`에 반영. `AIEDGE_FEEDBACK_DIR` env var.
- `analyze` / `analyze-8mb`에 `--rootfs <DIR>`가 추가되었습니다.
  다층 패킹 펌웨어에서 추출 실패 시, 수동/사전 추출 rootfs를 바로 주입할 수 있습니다.
- extraction stage에 품질 게이트가 추가되어 파일 수가 너무 적으면 `partial` + 경고로 표시됩니다.
- inventory 산출물이 확장되었습니다.
  - `stages/inventory/binary_analysis.json` (+ 바이너리별 하드닝 데이터)
  - `inventory.json.quality`
  - `inventory.json.binary_analysis_summary`
- `firmware_profile`은 ELF 교차검증(`arch_guess`, `elf_hints`)을 포함해 RTOS 오탐을 줄입니다.
- `firmware_handoff.json`이 SCOUT에서 자동 생성됩니다(분석/재실행 모두).
- `./scout` 래퍼가 우선 사용되며, 긴 `PYTHONPATH=... python3 -m aiedge` 호출은 보조 수단입니다.
- `dynamic_validation`과 `exploit_autopoc`가 **증거 번들(evidence bundle)**을 통해 연결되어, 실시간으로 D/E/V 우선순위 판독이 가능해졌습니다.
- 런타임 통신 모델이 별도 stage로 산출됩니다.
  - `stages/graph/communication_graph.json`
  - `stages/graph/communication_matrix.json` / `.csv`
  - Neo4j용 `communication_graph.cypher`, `communication_graph.queries.cypher`
- TUI/뷰어에 위협·런타임·자산 패널이 추가되어 한 화면에서 흐름을 볼 수 있습니다.
- `AIEDGE_PRIV_RUNNER`는 상대 경로를 지원하며, `run_dir` 포함 다수 위치에서 안전하게 해석됩니다.
- SquashFS 추출이 **재귀적 BFS 큐**로 개선되었습니다 (깊이 제한 4, 오프셋 기반 매직 스캔으로 벤더 래퍼 `.cv2` 등 대응).
- **심링크 containment** 적용: 추출된 심링크 대상이 `run_dir` 밖으로 탈출하면 스킵 및 `limitations[]`에 기록합니다.
- Findings에 **브릿지 토큰 탐지** 추가: `sprintf`/`snprintf`/`strcat`/`strcpy`가 `system`/`popen`/`execve` 근처에 있으면 커맨드 인젝션 후보로 플래그합니다.
- 신규 **`web_ui` 스테이지**: 웹 콘텐츠 디렉토리(`www/`, `htdocs/`, `webroot/`, `cgi-bin/`)의 HTML/JS에서 보안 패턴(XSS 싱크, API 서피스, WebSocket 등)을 스캔합니다. `stages/web_ui/web_ui.json` 산출.

---

## 아키텍처 요약

```
펌웨어
  ├─ 추출/프로파일링
  ├─ 인벤토리(파일/바이너리/하드닝 분석)
  ├─ 공격면 매핑(네트워크/서비스/프로토콜/엔트리포인트)
  ├─ 웹 UI 보안 스캔(HTML/JS 패턴, API 스펙 탐지)
  ├─ 취약점 패턴 + 체인 후보(브릿지 토큰 탐지 포함)
  ├─ LLM 트리아지 (보안 컨텍스트 기반 우선순위, haiku/sonnet/opus 자동 선택)
  ├─ 동적 검증(3-Tier: FirmAE/QEMU user-mode/rootfs)
  ├─ PoC/자동 공격체인 시도(유형별 템플릿 + LLM)
  └─ verified_chain report 생성
```

각 단계는 `aiedge-runs/<ts>_sha256-.../` 아래에 증거를 남깁니다.

---

## 빠른 시작 (CLI)

### 기본 분석

```bash
cd /path/to/SCOUT
./scout analyze firmware.bin \
  --ack-authorization --no-llm \
  --case-id my-analysis \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory

# 추출이 약한 타깃(다층 포맷)에서는 사전 추출 rootfs를 직접 주입
./scout analyze firmware.img \
  --ack-authorization --no-llm \
  --case-id my-analysis \
  --rootfs /path/to/extracted/rootfs
```

### 전체 프로필(권장: exploit 모드)

```bash
./scout analyze firmware.bin \
  --ack-authorization \
  --case-id my-analysis \
  --profile exploit \
  --exploit-flag lab \
  --exploit-scope lab-only \
  --exploit-attestation authorized
```

### 기존 분석 재실행 / 특정 스테이지만 수행

```bash
./scout stages aiedge-runs/<run_id> \
  --stages llm_synthesis,dynamic_validation,exploit_autopoc \
  --time-budget-s 900
```

환경변수(필요 시):

```bash
export AIEDGE_LLM_CHAIN_TIMEOUT_S=180
export AIEDGE_LLM_CHAIN_MAX_ATTEMPTS=5
export AIEDGE_AUTOPOC_LLM_TIMEOUT_S=180
export AIEDGE_AUTOPOC_LLM_MAX_ATTEMPTS=4

export AIEDGE_LLM_DRIVER=codex              # LLM provider (기본: codex)
export AIEDGE_EMULATION_IMAGE=scout-emulation:latest  # Tier 1 Docker 이미지
export AIEDGE_FIRMAE_ROOT=/opt/FirmAE        # FirmAE 경로 (기본)
export AIEDGE_FEEDBACK_DIR=aiedge-feedback    # Terminator 피드백 디렉토리

export AIEDGE_PORTSCAN_TOP_K=1000    # 힌트/우선 포트 + top-k 스캔 개수
export AIEDGE_PORTSCAN_START=1
export AIEDGE_PORTSCAN_END=65535
export AIEDGE_PORTSCAN_WORKERS=128
export AIEDGE_PORTSCAN_BUDGET_S=120
export AIEDGE_PORTSCAN_FULL_RANGE=0  # 1: 전체 포트 범위 스캔, 0(기본): top-k 중심 우선 스캔

# 전체 범위 스캔이 필요한 경우:
# export AIEDGE_PORTSCAN_FULL_RANGE=1
```

### no-new-privileges 환경에서 동적 단계 실행

```bash
export AIEDGE_PRIV_RUNNER='./scripts/priv-run'
./scout stages aiedge-runs/<run_id> --stages dynamic_validation,exploit_autopoc
```

---

## 결과 검증(권장)

```bash
python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_aiedge_analyst_report.py --run-dir aiedge-runs/<run_id>

python3 scripts/verify_run_dir_evidence_only.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_network_isolation.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_exploit_meaningfulness.py --run-dir aiedge-runs/<run_id>
python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>
```

네 개의 verifier 모두 통과 + digest 무결성 확인이 기본 운영 기준입니다.

---

## 터미널 UI / 뷰어

```bash
./scout tui aiedge-runs/<run_id>            # one-shot (기본)
./scout tw aiedge-runs/<run_id> -t 2 -n 20   # watch 모드
./scout ti aiedge-runs/<run_id>              # interactive
./scout to aiedge-runs/<run_id>              # once 모드
./scout serve aiedge-runs/<run_id>            # 웹 뷰어
```

인터랙티브 키:

- 이동: `j/k`, `↑/↓`, `g/G`
- 패널: `c`(후보), `t`(위협), `m`(런타임 모델), `a`(자산/프로토콜)
- 갱신: `r`, 종료: `q`

---

## run_dir 핵심 구조

```text
aiedge-runs/<run_id>/
├─ manifest.json
├─ firmware_handoff.json
├─ input/firmware.bin
├─ stages/
│  ├─ extraction/
│  ├─ firmware_profile/
│  ├─ inventory/
│  │  └─ binary_analysis.json  (+ 바이너리별 하드닝 데이터)
│  ├─ surfaces/
│  ├─ web_ui/
│  │  └─ web_ui.json
│  ├─ findings/
│  ├─ llm_triage/
│  │  └─ triage.json
│  ├─ dynamic_validation/
│  ├─ exploit_autopoc/
│  └─ graph/
└─ report/
   ├─ report.json
   ├─ analyst_overview.json
   └─ analyst_digest.json / .md
```

---

## 계약 문서(Contracts)

현재 문서들과 스키마는 `docs/` 폴더에서 관리합니다.

- `docs/status.md`: 현재 구현 상태
- `docs/runbook.md`: 운영 절차/검증 플로우
- `docs/aiedge_firmware_artifacts_v1.md`: 산출물 스키마
- `docs/aiedge_report_contract.md`: 최종 리포트 계약
- `docs/analyst_digest_contract.md`: digest 스키마
- `docs/analyst_viewer_cockpit_mapping.md`: 뷰어/카드 매핑
- `docs/verified_chain_contract.md`: verified_chain 계약
- `docs/codex_first_agent_policy.md`: LLM/Codex 실행 정책

---

## 보안 및 윤리

SCOUT는 아래 목적의 통제된 환경에서 사용해야 합니다.

- 사전 승인된 보안 점검(벤더 협의)
- 연구/랩 환경에서의 재현성 높은 취약점 분석
- CTF 및 교육 환경

다음은 기본 보안 제약입니다.

- 외부 네트워크 비활성에서의 동적 검증 권장
- PoC 실행은 실험실 승인/범위 제어 조건에서만 수행
- weaponized payload 미포함; 기본 템플릿은 안전한 PoC 뼈대
- 최종 **confirmed/verified** 판단은 동적 증거 없이는 불가

---

## 원문/추가 정보

- English README: `README.md`
- 본 문서 한글판입니다. 영어판이 더 자세한 내용이나 최신 변경이 우선입니다.

---

MIT License
