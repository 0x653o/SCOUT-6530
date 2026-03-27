# SCOUT v2.0 Roadmap: LLM/Agent AI Integration & Benchmark Strategy

> SCOUT는 "Firmware-to-Exploit Evidence Engine"이다.
> LLM은 이 엔진의 **부스터**이지, 의존성이 아니다.

## 1. 현재 위치 (As-Is)

### 1.1 SCOUT v1.0 핵심 자산

| 자산 | 설명 |
|------|------|
| **34-stage deterministic pipeline** | JSON artifact + SHA-256 manifest로 완전 격리, `--no-llm`으로 재현 가능 |
| **Evidence-first 아키텍처** | 모든 finding = (file_path, byte_offset, sha256, rationale) 4-tuple |
| **5단계 승격 정책** | dismissed → candidate → high_confidence_static → confirmed → verified_chain |
| **Confidence cap** | 정적 분석 전용 finding은 0.60 hard cap (`confidence_caps.py`) |
| **산업 표준 출력** | SARIF 2.1.0, CycloneDX 1.6+VEX, SLSA L2 attestation |
| **Zero dependency** | Python stdlib only, air-gapped 배포 가능 |
| **3-tier emulation** | FirmAE Docker → QEMU user-mode → GDB probe |
| **MCP 서버** | 12-tool, Claude Code/Desktop 자율 구동 |

### 1.2 현재 LLM 개입 지점

```
Pipeline Stage          LLM 사용          현재 한계
─────────────────────────────────────────────────────
ghidra_analysis         없음              raw decompile 출력만, 의미론 해석 없음
llm_triage              codex/claude      positive bias (confirmation bias)
llm_synthesis           codex/claude      보고서 품질 향상만, finding 품질에 무관
exploit_autopoc         codex/claude      단발 생성, iterative refinement 없음
```

### 1.3 핵심 미달성 목표

- **verified_chain end-to-end 도달 사례 0건** — 아키텍처는 있으나 실증 없음
- **FPR 정량 데이터 부족** — quality gate 임계값(FPR ≤ 0.1) 존재하나 대규모 검증 미수행
- **exploit chain 자동 조립 불가** — 개별 finding은 뽑지만 multi-step path 추론 안 됨

---

## 2. 설계 원칙 (Iron Laws)

### 2.1 LLM은 "제안자", 증거 게이트가 "결정자"

```
┌─────────────┐     proposal     ┌──────────────────┐     승인/거부     ┌──────────────┐
│  LLM Layer  │ ──────────────→ │  Evidence Gate    │ ──────────────→ │  Artifact    │
│  (non-det)  │                 │  (deterministic)  │                 │  (immutable) │
└─────────────┘                 └──────────────────┘                 └──────────────┘
                                 confidence_caps.py
                                 exploit_tiering.py
                                 validate_handoff()
```

- LLM이 "confirmed"라 해도 동적 증거 없으면 0.60 cap 적용
- LLM 출력은 항상 `llm_trace/`에 input/output/latency/cost 기록
- `--no-llm` 플래그로 LLM 레이어 전체 비활성화 시 기존 파이프라인 100% 동작

### 2.2 Additive, Not Dependent

LLM 통합은 기존 stage에 **후처리(post-processor)** 또는 **중간 필터(filter)**로 삽입한다. 새 stage를 추가하되, 기존 stage의 동작을 변경하지 않는다.

### 2.3 Cost-Aware Tiered Routing

| 모델 티어 | 용도 | per-call 비용 | 호출 빈도 |
|-----------|------|---------------|-----------|
| **haiku** | 함수 분류, 패턴 매칭 | ~$0.001 | 수천 회/run |
| **sonnet** | adversarial triage, 맥락 판단 | ~$0.01 | 수십 회/run |
| **opus** | chain construction, PoC 생성 | ~$0.10 | 1-5회/run |

**예산 기준:** 전체 LLM 비용 ≤ $5/firmware → haiku 70% / sonnet 20% / opus 10%

---

## 3. LLM 삽입 지점 (ROI 순)

### Phase 1: Semantic Function Classifier (ROI 최고)

**현재 병목:** Ghidra decompile → raw C 출력 수천 개 함수 → 패턴 매칭("strcpy 있음") → 맥락 없는 FP 대량 발생

**목표:** decompiled function → semantic category annotation → source-sink graph enrichment

```
[현재]
Ghidra → raw_functions.json → 패턴 매칭 → FP 다량

[Phase 1 이후]
Ghidra → raw_functions.json
  → 정적 필터 (dangerous API 호출 포함 함수만)
  → haiku: 함수 분류 (auth_check / command_handler / crypto_op / benign / ...)
  → 고위험 함수만 sonnet: 정밀 취약점 분석
  → source-sink graph에 semantic annotation 추가
```

**관련 연구:**
- LLM4Decompile (2024) — LLM 기반 디컴파일 결과 향상, 재컴파일 성공률 향상
- GPT-4를 활용한 바이너리 함수 유사도 분석 (2024) — 함수 의미론 이해에 LLM 활용
- VulDeePecker / SySeVR 계열 — 딥러닝 기반 취약점 탐지 (코드 슬라이스 입력)

**구현 위치:** `src/aiedge/semantic_classifier.py` (신규), `ghidra_analysis` stage 후처리

**예상 효과:** source-sink graph precision 대폭 개선, FPR 감소

---

### Phase 2: Adversarial Triage (FPR 직접 감소)

**현재 병목:** `llm_triage`가 positive-only ("이 finding 유효한가?") → confirmation bias

**목표:** advocate-critic 쌍으로 adversarial self-review

```
Finding (confidence ≥ 0.5)
  → Advocate (sonnet): "이 finding이 왜 exploitable한지 주장하라"
  → Critic (sonnet): "이 finding이 왜 NOT exploitable한지 반박하라"
  → Rebuttal 강도에 따라 confidence 조정
  → 강한 rebuttal → confidence 감점 → dismissed 강등 가능

예시:
  Finding: "lighttpd CGI handler에서 command injection"
  Advocate: "user input → system() 직접 전달, 인증 없음"
  Critic: "BUT: 1) ';|&' 필터 존재 (offset 0x4a2c)
           2) chroot jail 설정됨
           3) LAN-only ACL 뒤에 있음"
  → confidence 0.75 → 0.45 (dismissed)
```

**관련 연구:**
- Constitutional AI (Anthropic, 2022) — LLM self-critique 패턴
- LLM-as-Judge (2024) — adversarial 평가에서 단일 LLM보다 advocate-critic 쌍이 정확
- SCOUT Terminator의 triager_sim.md — H1 triager 롤플레이 패턴 (검증됨)

**구현 위치:** `src/aiedge/adversarial_triage.py` (신규), `llm_triage` 후단에 삽입

**비용 최적화:** confidence < 0.5인 finding은 skip (이미 dismissed급)

**예상 효과:** FPR 0.1 → 0.05 수준

---

### Phase 3: Exploit Chain Construction (핵심 미달성 목표)

**현재 병목:** 개별 finding은 뽑지만, "auth bypass + command injection + weak permissions = kill chain"이라는 연결을 자동으로 못 함

**목표:** 기존 artifact(findings, graphs, binary analysis)를 입력으로 multi-step attack path 추론

```
[입력]
- findings (pattern_scan.json, credential_mapping.json)
- source-sink graph (source_sink_graph.json)
- communication graph (communication_graph.json)
- binary hardening data (binary_analysis.json)
- reachability data (reachability.json)

[opus LLM 태스크]
"외부 공격자 → code execution까지의 multi-step 경로를 구성하라.
 각 step에 전제조건과 증거를 명시하라."

[출력: chains.json]
{
  "chains": [{
    "id": "chain-001",
    "steps": [
      {"finding_id": "F-012", "primitive": "unauth_access", ...},
      {"finding_id": "F-034", "primitive": "command_injection", ...},
      {"finding_id": "F-056", "primitive": "persistence", ...}
    ],
    "confidence": 0.72,
    "missing_evidence": ["dynamic validation of step 2"]
  }]
}
```

**관련 연구:**
- AutoAttacker (2024) — LLM 기반 자동 공격 경로 탐색
- PentestGPT (2023) — penetration testing에 LLM 활용, multi-step reasoning
- AttackGen — MITRE ATT&CK 기반 시나리오 자동 생성

**구현 위치:** `src/aiedge/chain_constructor.py` (신규), `exploit_chain` stage 대체/보강

**비용:** firmware당 1-3회 opus 호출, 전체 예산의 ~10%

**예상 효과:** verified_chain 도달 가능성 확보

---

### Phase 4: PoC Generation + Verification Loop (confirmed 자동 도달)

**현재 병목:** `exploit_autopoc`이 PoC를 단발 생성, 실패 시 피드백 루프 없음

**목표:** generate → emulate → feedback → revise 반복 루프

```
Chain step (from Phase 3)
  → LLM(sonnet): PoC skeleton 생성 (pwntools 기반)
  → QEMU user-mode 또는 FirmAE에서 실행
  → 성공: SCOUT_MARKER 출력 감지 → confirmed 승격
  → 실패: crash log + GDB output을 LLM에 피드백
  → LLM: offset/payload 수정한 PoC v2 생성
  → 최대 5회 반복, budget 소진 시 중단
  → 모든 시도를 poc_trace/에 기록 (재현 가능)
```

**관련 연구:**
- SWE-bench (2024) — LLM의 iterative debugging 능력 벤치마크
- Cybench (2024) — LLM agent의 CTF 문제 풀이 벤치마크
- DARPA AIxCC (2024) — AI 기반 자동 취약점 발견 및 패치 대회

**구현 위치:** `src/aiedge/poc_loop.py` (신규), `exploit_autopoc` + `poc_validation` 통합

**예상 효과:** confirmed 등급 자동 도달, verified_chain 1건 이상 달성

---

### Phase 5: Cross-Run Learning (장기)

**목표:** 이전 분석 결과를 다음 분석에 활용

```
Run N 완료 → llm_trace/ + findings를 AIEDGE_FEEDBACK_DIR에 저장
Run N+1 시작 → 동일 벤더/아키텍처의 이전 결과 참조
  → "D-Link DIR-xxx에서 이전에 command injection이 /cgi-bin/webcm에서 발견됨"
  → 유사 경로 우선 탐색 → 시간 절감
```

**관련 연구:**
- FirmRec (CCS 2024) — recurring vulnerability detection, 320 firmware, 642 vulns
  - 동일 코드베이스의 다른 firmware에서 반복 발생하는 취약점 패턴 감지
- VERI (Computers & Security 2022) — 28,890 firmware에서 cross-vendor 취약점 상관관계 발견

---

## 4. Agent 아키텍처: Terminator 통합 방향

### 4.1 Terminator에서 가져올 패턴

| 패턴 | 출처 | SCOUT 구현 |
|------|------|-----------|
| **Early Critic** | reverser 직후 critic 삽입 | Phase 1 classifier → Phase 2 triage 연쇄 |
| **Triager Simulation** | H1 triager 롤플레이 | adversarial_triage 모듈 |
| **교훈 누적** | knowledge/ 디렉토리 | llm_trace/ + AIEDGE_FEEDBACK_DIR |

### 4.2 Terminator에서 가져오지 않을 것

| 패턴 | 이유 |
|------|------|
| 17-agent 분리 | Claude Code Agent Teams 의존, 에이전트 간 정보 손실 |
| bypassPermissions | SCOUT는 assert_under_dir() 코드 레벨 강제가 더 안전 |
| 프롬프트 핸드오프 | 단일 orchestrator + MCP 도구 호출 ReAct 루프가 더 효율적 |

### 4.3 이상적 Agent 구조

```
┌─────────────────────────────────────────────────────┐
│                SCOUT MCP Orchestrator                │
│   (단일 ReAct agent, MCP 12-tool 직접 호출)         │
│                                                     │
│   loop:                                             │
│     1. observe: 현재 stage 결과 읽기                │
│     2. think: 다음 행동 결정 (LLM)                  │
│     3. act: MCP tool 호출 or stage 실행             │
│     4. verify: evidence gate 통과 확인              │
│     5. repeat until verified_chain or budget exhaust│
└─────────────────────────────────────────────────────┘
```

---

## 5. 벤치마크 전략

### 5.1 사용 가능한 데이터셋

| 데이터셋 | 규모 | 특징 | SCOUT 활용 |
|----------|------|------|-----------|
| **FirmAE** (ACSAC 2020) | 1,124 images, 8 vendors | 에뮬레이션 성공률 ground truth | 에뮬레이션 비교 기준선 |
| **FirmRec** (CCS 2024) | 320 images, 642 vulns | exploitation-validated ground truth | **end-to-end 정확도 평가** (최적) |
| **FirmSec** (ISSTA 2022) | 34,136 images, 429 CVEs | TPC-CVE 매핑 | SCA/SBOM 정확도 평가 |
| **WUSTL-CSPL** (2024) | 157,141 images, 204 vendors | 최대 규모 corpus | 대규모 스케일 테스트 |
| **VERI** (2022) | 28,890 images, 524 CVEs | cross-vendor 분석 | patch lag 분석 |

### 5.2 평가 지표 매핑

```
SCOUT Stage                  Metric                  Baseline (Literature)
──────────────────────────────────────────────────────────────────────────
extraction                   Unpack success rate      Binwalk: ~90%
emulation                    Boot + web service       FirmAE: 79.36%
                                                      EMBA 2.0: 95% (self-reported)
sbom + cve_scan              SCA precision/recall     VERI: 97%/96%
                                                      BinaryAI: 86%/65%
findings (static)            TPR / FPR                HermeScan: 81% TPR
                                                      SaTC: 42% TPR
exploit_chain + poc           Chain completeness       없음 (SCOUT가 최초 시도)
전체 pipeline                 Time per firmware        HermeScan: 1.14h avg
                                                      FirmAE: ~13s emulation only
```

### 5.3 FirmAE 벤치마크 실행 계획

현재 11.9GB 데이터셋 다운로드 중. 완료 후:

```bash
# 1. 압축 해제 및 벤더별 분류
./scripts/unpack_firmae_dataset.sh

# 2. Quick test (10개, 2분/개)
./scripts/benchmark_firmae.sh --max-images 10 --time-budget 120

# 3. Full static pipeline (1,124개, 10분/개)
./scripts/benchmark_firmae.sh --parallel 8 --time-budget 600

# 4. 결과 비교 리포트 자동 생성
# → benchmark-results/firmae-YYYYMMDD_HHMM/benchmark_report.txt
```

### 5.4 FirmRec 벤치마크 (추후)

FirmRec의 642 exploitation-validated 취약점에 대해:
- SCOUT 정적 파이프라인의 detection rate 측정
- Phase 1-4 LLM 통합 전후 비교
- Adversarial triage 적용 전후 FPR 변화 측정

---

## 6. 구조적 부채 해소 (병행)

LLM 통합과 병행하여 해결해야 할 기술 부채:

| 부채 | 영향 | 우선순위 |
|------|------|----------|
| `__main__.py` 4,500줄 모놀리스 | 테스트 격리 불가, 컨트리뷰터 진입장벽 | **높음** |
| `_assert_under_dir()` 26개 로컬 복사본 | 보안 critical 코드 divergence 위험 | **높음** |
| binwalk-only unpacking | extraction 실패 시 전체 파이프라인 무력화 | **중간** |
| fuzzing budget 1시간 기본값 | 임베디드 타겟에서 유의미한 결과 부족 | **낮음** |

---

## 7. 타임라인 (FirmAgent 분석 반영)

```
Phase 0 (현재)     FirmAE 벤치마크 + 기존 데이터 정리                    ← 완료
                   ↓
Phase 1 (1-2주)    Ghidra Decompile Refinement + Semantic Classifier
                   → LLM4Decompile-Ref 또는 DeGPT 패턴으로 Ghidra 출력 정제
                   → haiku 함수 분류 → source-sink graph enrichment
                   ↓
Phase 2 (2-4주)    FirmAgent 핵심 기법 채택
                   2a. Csource 런타임 식별 (QEMU TCG taint monitoring)
                       → emulation → csource_identification stage 추가
                   2b. LLM Inter-Procedural Taint Propagation
                       → reachability → taint_propagation stage 추가
                   2c. Few-shot FP 검증 (3패턴: sanitizer/non-propagating/sysfile)
                       → llm_triage 보강
                   ↓
Phase 3 (4-6주)    Directed Fuzzing + PoC Loop
                   → Sink-distance 기반 directed fuzzing (AFLGo 통합)
                   → Fuzzing-seeded PoC generation (reachable testcase → exploit_autopoc)
                   → generate-test-revise 반복 루프
                   ↓
Phase 4 (6-8주)    Chain Construction + Verification
                   → opus로 multi-step attack path 추론
                   → verified_chain 1건 이상 달성 목표
                   → FirmRec 320개로 chain 품질 평가
                   ↓
Phase 5 (장기)     Pandawan Tier 1.5 통합 + Cross-Run Learning
                   → Pandawan 안정화 추적, kernel module 커버리지 확보
                   → WUSTL 157K 대규모 벤치마크
```

### FirmAgent에서 채택할 기술 (SCOUT v2.0 신규 스테이지)

```
기존 파이프라인:
  ... → emulation → fuzzing → exploit_gate → ...

v2.0 파이프라인 (FirmAgent 기법 반영):
  ... → emulation
      → csource_identification (NEW: QEMU TCG taint → 100% precision source)
      → taint_propagation (NEW: LLM inter-procedural data-flow)
      → fuzzing (ENHANCED: sink-distance directed + keyword dictionary)
      → exploit_gate
      → exploit_autopoc (ENHANCED: fuzzing-seeded PoC)
      → ...
```

---

## 8. 성공 기준

| 마일스톤 | 측정 가능한 기준 |
|----------|-----------------|
| Phase 1 완료 | FirmAE 1,124개 대상 함수 분류 완료, source-sink graph annotation 추가 |
| Phase 2 완료 | FirmRec 642개 취약점 대상 FPR ≤ 0.05 달성 |
| Phase 3 완료 | 자동 생성된 exploit chain 1개 이상이 수동 검증 통과 |
| Phase 4 완료 | firmware.bin → verified_chain end-to-end 1건 이상 |
| 전체 완료 | SCOUT + LLM이 FirmAE 에뮬레이션 없이도 FirmAE보다 많은 취약점 발견 |

---

## 9. 핵심 관련 연구 (2023-2026)

### 9.1 SCOUT 아키텍처를 독립 검증한 연구

#### FirmAgent (NDSS 2026) — SCOUT와 동일 아키텍처, 91% precision

> Tsinghua NETSEC Lab. "Leveraging Fuzzing to Assist LLM Agents with IoT Firmware Vulnerability Discovery"

SCOUT와 **독립적으로 동일한 파이프라인 구조에 수렴**한 연구:
- Fuzzing → LLM Agent 1 (taint analysis) → LLM Agent 2 (PoC refinement)
- **182 취약점**, **91% precision**, **140 novel**, **17 CVE 할당**
- SCOUT의 `fuzzing → reachability/surfaces → exploit_autopoc` 시퀀스와 정확히 대응

**시사점:** SCOUT의 파이프라인 설계가 최적에 가깝다는 독립 검증. 91% precision은 SCOUT quality gate (≥ 0.9)의 현실성을 뒷받침.

- [Paper](https://www.ndss-symposium.org/ndss-paper/firmagent-leveraging-fuzzing-to-assist-llm-agents-with-iot-firmware-vulnerability-discovery/)
- [PDF](https://netsec.ccert.edu.cn/files/papers/ndss26-firmagent.pdf)

#### LARA (USENIX Security 2024) — LLM-Aided IoT Firmware Vuln Detection

- LLM + 정적 패턴 결합: **504 true vulns**, precision 73% → 83.6%
- **245 zero-day**, 57 devices
- SCOUT의 `web_ui` + `endpoints` 스테이지에 직접 적용 가능

- [Paper](https://www.usenix.org/system/files/usenixsecurity24-zhao.pdf)

### 9.2 에뮬레이션: FirmAE 이후 (Pandawan이 후계자)

#### Pandawan (USENIX Security 2024) — FirmAE 직접 대체

> Boston University. 1,520 firmware, Firmadyne/FirmAE/FirmSolo와 직접 비교

| 지표 | vs FirmAE | vs FirmSolo |
|------|-----------|-------------|
| User-level 프로그램 | **+6%** | — |
| User code basic blocks | **+21%** | — |
| Kernel modules | — | **+9%** |
| Kernel basic blocks | — | **+26%** |

**SCOUT 적용:** `emulation` 스테이지 백엔드를 FirmAE → Pandawan으로 교체. 아키텍처 변경 불필요.

- [Paper](https://www.usenix.org/conference/usenixsecurity24/presentation/angelakopoulos)
- [GitHub](https://github.com/BUseclab/Pandawan)

#### Greenhouse (USENIX Security 2023) — Single-Service Rehosting

전체 시스템 대신 개별 서비스만 user-space에서 실행. FirmAE 실패 시 fallback으로 활용.

#### FirmSolo (USENIX Security 2023) — Kernel Module Emulation

커널 모듈 호환성 문제 해결. FirmAE 실패 원인의 상당수 커버.

#### SURGEON (NDSS BAR 2024) — Bare-Metal Rehosting

Linux 없는 RTOS/bare-metal 펌웨어를 Linux user-space로 변환. SCOUT의 커버리지를 비Linux 펌웨어로 확장.

### 9.3 LLM + Binary Analysis

#### DeGPT (NDSS 2024) — Ghidra 출력 최적화

3-role LLM (referee/advisor/operator)으로 디컴파일 출력 품질 향상. **인지 부하 24.4% 감소**, 62.9% 함수에 의미 있는 주석 생성.

- [Paper](https://www.ndss-symposium.org/ndss-paper/degpt-optimizing-decompiler-output-with-llm/)
- [GitHub](https://github.com/PeiweiHu/DeGPT)

#### LLM4Decompile (EMNLP 2024) — 오픈소스 디컴파일 LLM

1.3B-33B 파라미터, Ghidra 출력 정제 시 **+16.2% 향상**. GPT-4o 대비 **+100% re-executability**. **Ollama로 로컬 배포 가능** → SCOUT의 `OllamaDriver`로 직접 연결.

- [arXiv](https://arxiv.org/abs/2403.05286)
- [GitHub](https://github.com/albertan017/LLM4Decompile)

#### LLMxCPG (USENIX Security 2025) — Code Property Graph + LLM

CPG 쿼리로 취약점 관련 코드 슬라이스만 추출 → 코드 크기 **67-91% 감소** → F1 **15-40% 향상**. SCOUT의 `reachability` + `surfaces` 스테이지 보강에 적합.

- [GitHub](https://github.com/qcri/llmxcpg)

### 9.4 LLM + Fuzzing

#### ChatAFL (NDSS 2024) — LLM-Guided Protocol Fuzzing

RFC에서 프로토콜 문법 자동 추출 → state coverage **+30%**, state transitions **+47.6%** (48x 빠르게 도달). **9 unknown bugs**. IoT 펌웨어 네트워크 서비스(HTTP, MQTT, CoAP)에 직접 적용 가능.

- [GitHub](https://github.com/ChatAFLndss/ChatAFL)

#### Google OSS-Fuzz-Gen (2024) — LLM Harness 자동 생성

LLM으로 fuzz harness 자동 생성 → 272 프로젝트, **370,000+ 줄 신규 커버리지**, **26 confirmed vulns** (CVE-2024-9143 포함, 20년 된 OpenSSL 버그). SCOUT의 harness 수동 작성 문제를 해결.

- [GitHub](https://github.com/google/oss-fuzz-gen)

### 9.5 Automated Exploit Generation

#### LLM Agents Exploit One-Day CVEs (arXiv 2024)

GPT-4 agent가 CVE 설명 제공 시 **15개 실제 CVE 중 87% 자율 익스플로잇** 성공. CVE 설명 없으면 7%. SCOUT의 `cve_scan → exploit_autopoc` 파이프라인의 유효성을 검증.

- [arXiv 2404.08144](https://arxiv.org/abs/2404.08144)

#### HPTSA — Teams of LLM Agents Exploit Zero-Days (arXiv 2024)

계층적 planning agent + 특화 subagent → 단일 agent 대비 **4.3x** 향상. 14개 실제 zero-day 대상. SCOUT의 multi-stage 파이프라인 구조를 독립 검증.

- [arXiv 2406.01637](https://arxiv.org/abs/2406.01637)

#### Microsoft Security Copilot — Bootloader취약점 발견 (2025)

CodeQL + AFL++ + LLM으로 GRUB2, U-Boot, Barebox 취약점 발견. **수동 리뷰 1주 절감**. SCOUT의 3-layer (정적+동적+LLM) 아키텍처의 산업 검증.

- [Blog](https://www.microsoft.com/en-us/security/blog/2025/03/31/analyzing-open-source-bootloaders-finding-vulnerabilities-faster-with-ai/)

---

## 10. 즉각 실행 가능한 3대 액션

| 우선순위 | 액션 | 근거 |
|----------|------|------|
| **1** | `emulation` 백엔드를 **Pandawan**으로 교체 | FirmAE 직접 후속, 동일 벤치마크에서 +21% basic block 커버리지, GitHub 공개, 아키텍처 변경 불필요 |
| **2** | `ghidra_analysis` 후처리에 **LLM4Decompile-Ref** 추가 | 오픈소스, Ollama 배포 가능, +16.2% 개선, 모든 downstream LLM 스테이지 품질 향상 |
| **3** | **FirmAgent 아키텍처 분석** 후 SCOUT Phase 3-4에 반영 | SCOUT 파이프라인의 독립 검증, 91% precision / 140 novel vulns 벤치마크 기준선 제공 |

---

## References

### Firmware Analysis & Emulation

- FirmAE (ACSAC 2020) — https://doi.org/10.1145/3427228.3427294
- FirmAgent (NDSS 2026) — https://netsec.ccert.edu.cn/files/papers/ndss26-firmagent.pdf
- Pandawan (USENIX Sec 2024) — https://github.com/BUseclab/Pandawan
- FirmRec (CCS 2024) — https://doi.org/10.1145/3658644.3670275
- FirmSec (ISSTA 2022) — https://doi.org/10.1145/3533767.3534366
- LARA (USENIX Sec 2024) — https://www.usenix.org/system/files/usenixsecurity24-zhao.pdf
- HermeScan (NDSS 2024)
- Greenhouse (USENIX Sec 2023) — https://www.usenix.org/conference/usenixsecurity23/presentation/tay
- FirmSolo (USENIX Sec 2023)
- SURGEON (NDSS BAR 2024)
- EMBA — https://github.com/e-m-b-a/emba
- WUSTL-CSPL Dataset (157K images) — https://github.com/WUSTL-CSPL/Firmware-Dataset

### LLM + Binary Analysis

- DeGPT (NDSS 2024) — https://github.com/PeiweiHu/DeGPT
- LLM4Decompile (EMNLP 2024) — https://github.com/albertan017/LLM4Decompile
- LLMxCPG (USENIX Sec 2025) — https://github.com/qcri/llmxcpg
- VulBinLLM (arXiv 2025) — https://arxiv.org/abs/2505.22010

### LLM + Fuzzing

- ChatAFL (NDSS 2024) — https://github.com/ChatAFLndss/ChatAFL
- Fuzz4All (ICSE 2024) — https://github.com/fuzz4all/fuzz4all
- OSS-Fuzz-Gen — https://github.com/google/oss-fuzz-gen
- ICSQuartz (NDSS 2025)

### Automated Exploitation

- LLM Exploit One-Day CVEs (arXiv 2024) — https://arxiv.org/abs/2404.08144
- HPTSA Zero-Day Exploitation (arXiv 2024) — https://arxiv.org/abs/2406.01637
- PwnGPT (ACL 2025) — https://aclanthology.org/2025.acl-long.562.pdf
- Microsoft Security Copilot (2025) — https://www.microsoft.com/en-us/security/blog/2025/03/31/

### Evaluation & Benchmarks

- BinaryAI (ICSE 2024) — Binary SCA benchmark
- LibScan (USENIX Security 2023) — Library detection benchmark
- OWASP FSTM — Firmware Security Testing Methodology
- ARES 2023 — Linux IoT benchmark generator
- VERI (Computers & Security 2022) — 28,890 firmware, 524 CVEs
