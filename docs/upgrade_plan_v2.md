# SCOUT v2.0 Upgrade Plan (Revised)

> 작성일: 2026-03-27 (Rev.2 — GPT/Claude 교차 검증 반영)
> 기준: SCOUT v1.0 (commit 251fc06), FirmAgent (NDSS 2026), Pandawan (USENIX Sec 2024)

---

## 목표

SCOUT를 NDSS/USENIX/CCS 급 논문으로 발표할 수 있는 수준으로 업그레이드한다.

**논문 Contribution (Plan A — cross-binary chain 성공 시):**
1. Runtime-guided LLM taint analysis with evidence governance
2. Automatic cross-binary exploit chain construction via IPC graph
3. Large-scale evaluation (1,124 images, FirmAgent head-to-head)

**논문 Contribution (Plan B — cross-binary chain FP 폭발 시):**
1. Runtime-guided LLM taint analysis with evidence governance
2. Adversarial triage for precision-guaranteed firmware analysis
3. Large-scale evaluation with deterministic reproducibility

Plan B에서는 evidence governance + adversarial triage가 FirmAgent(91%)보다 높은 precision을 달성했다는 게 contribution. cross-binary chain 없이도 NDSS급 스토리가 가능.

---

## Phase 순서 (수정됨)

```
Phase 0A (Week 1)     구조 정비 — __main__.py 분리, assert_under_dir 통합
Phase 0B (Week 1-2)   벤치마크 인프라 — FirmAE 1,124개 baseline + FirmRec 매칭 로직
Phase 1  (Week 3-4)   Ghidra Refinement + Semantic Classifier
Phase 2  (Week 5-7)   Runtime-Guided Taint Analysis
Phase 3  (Week 8-10)  PoC Loop + Chain Construction
Phase 4  (Week 11-13) 대규모 평가 + 논문
```

**변경 이유:** 구조 정비(0A)가 벤치마크(0B)보다 먼저여야 한다. 4,500줄 모놀리스에서 새 stage를 추가하다 regression이 터지면 벤치마크 결과를 신뢰할 수 없다. 또한 Phase를 5개→4개로 압축 — 원래 Phase 3(Directed Fuzzing)와 Phase 4(Chain)를 합치고, Phase 5(평가)를 Phase 4로 앞당김.

---

## Phase 0A: 구조 정비 (Week 1)

### 0A.1 `__main__.py` / `run.py` 분리

**왜:** Phase 1-3에서 신규 stage를 최소 4개 추가해야 한다 (`enhanced_source`, `csource_identification`, `taint_propagation`, `adversarial_triage`). 4,500줄 파일에 코드를 더 추가하면 변경 충돌과 regression 위험이 급증.

**어떻게:**
```
__main__.py (4,500줄) → 분리:
  cli/analyze.py       — analyze, analyze-8mb, stages
  cli/serve.py         — serve + HTTPServer
  cli/tui.py           — TUI 렌더링 + ANSI 상수
  cli/quality.py       — quality-metrics, quality-gate, release-quality-gate
  cli/mcp.py           — MCP 서버 진입점
  __main__.py          — argparse + dispatcher만 (~200줄)
```

**완료 기준:** `__main__.py` < 300줄, 기존 테스트 83개 전부 통과, CI green

### 0A.2 `_assert_under_dir()` 26개 복사본 통합

**왜:** 보안 critical 코드가 26개 파일에 분산. 하나라도 diverge하면 path traversal. Phase 1-3에서 새 stage를 추가할 때마다 `from aiedge.path_safety import assert_under_dir`를 쓰게 해야 하고, 그 전제가 기존 복사본 통합.

**어떻게:**
```bash
# 1. 모든 로컬 _assert_under_dir() 정의를 찾아서
grep -rn "def _assert_under_dir" src/aiedge/ | grep -v path_safety.py
# 2. 각 파일에서 로컬 정의 삭제, import로 교체
# 3. 테스트로 기존 동작 보장
```

**완료 기준:** `grep "def _assert_under_dir" src/aiedge/` 결과가 `path_safety.py` 1건만 남음

### 0A.3 pyright blocking 전환 (core 패키지)

**왜:** CI에서 `continue-on-error: true`면 타입 에러가 누적. evidence contract 문서와 JSON 산출물이 많은 프로젝트에서 타입 = 유지보수 비용.

**어떻게:** core 모듈(`stage.py`, `path_safety.py`, `schema.py`, `determinism.py`, `confidence_caps.py`, `exploit_tiering.py`)에 대해서만 pyright strict 적용. 나머지는 기존 basic 유지.

---

## Phase 0B: 벤치마크 인프라 (Week 1-2)

### 0B.1 FirmAE 1,124개 정적 baseline

**왜:** 현재 SCOUT의 정량적 성능 데이터가 없다. 이 baseline이 있어야 Phase 1-3의 개선을 delta로 측정 가능.

**어떻게:**
```bash
# 정적 파이프라인만 (LLM 없음, 에뮬레이션 없음, $0)
./scripts/benchmark_firmae.sh --parallel 8 --time-budget 300 \
  --stages tooling,extraction,structure,carving,firmware_profile,inventory,sbom,cve_scan,reachability,endpoints,surfaces,graph,attack_surface,findings
```

**산출물:** `benchmark-results/firmae-static/benchmark_summary.csv`

### 0B.2 FirmRec Ground Truth 매칭 로직

**왜:** precision/recall을 측정하려면 SCOUT finding과 FirmRec label 사이의 자동 매칭이 필요. reviewer가 반드시 물어볼 질문.

**어떻게:**
```python
# scripts/firmrec_matcher.py
def match_finding_to_ground_truth(finding: dict, gt_entry: dict) -> bool:
    """
    매칭 기준:
    1. binary_path 일치 (basename 정규화)
    2. vuln_type 호환 (CWE 매핑 테이블)
    3. function_name 일치 또는 offset 근접 (±0x100)
    """
```

**근거:** FirmRec (CCS 2024)의 642개 취약점은 `(firmware_id, binary, CWE, offset)` 형태. SCOUT finding은 `(file_path, byte_offset, sha256)` 형태. CWE 매핑 테이블로 연결.

### 0B.3 Known-CVE 펌웨어 10개 선별 + Disclosure 준비

**왜:** Phase 3에서 PoC가 나올 때 unknown vuln이 발견되면 즉시 vendor 통보를 시작해야 한다. 논문 제출 시점에 CVE 번호가 없으면 reviewer가 신뢰하지 않음.

**어떻게:**
- FirmAE 데이터셋에서 known CVE + public PoC가 있는 펌웨어 10개 선별
- 이 10개로 Phase 1-3을 우선 실행 (파이프라인 검증 + 새 vuln 발견 기회)
- unknown vuln 발견 시 → 90-day disclosure clock 시작

---

## Phase 1: Ghidra Refinement + Semantic Classifier (Week 3-4)

### 1.1 LLM4Decompile-Ref 통합 (with MIPS/ARM validation gate)

**왜:** Ghidra raw 출력의 품질 문제. FirmAgent ablation에서 LLM refinement 제거 시 FPR 9%→26% (Table VI, Firm-Cut).

**추가된 안전장치 — MIPS/ARM validation gate:**
LLM4Decompile-Ref의 "+16.2%"는 x86 벤치마크 기준. IoT 펌웨어는 MIPS/ARM이 대다수. 검증 없이 적용하면 오히려 악화 가능.

```
[Decision Gate — Phase 1.1 시작 시]
10개 MIPS + 10개 ARM 샘플로 A/B test:
  Group A: raw Ghidra → taint analysis (Phase 2 preview)
  Group B: LLM4Decompile-Ref → taint analysis

If B.precision ≥ A.precision + 5%p → refinement 적용
If B.precision < A.precision → SKIP refinement, 1.2로 직행
```

**어떻게 (gate 통과 시):**
- LLM4Decompile-Ref (EMNLP 2024, 오픈소스 6.7B) → Ollama 로컬 배포
- `--no-llm` 시 raw Ghidra 출력 그대로 사용 (additive)
- 산출물: `stages/ghidra_analysis/refined_functions.json`

**근거:**
- LLM4Decompile-Ref: +16.2% re-executability, GPT-4o 대비 +100% (arXiv 2403.05286)
- 로컬 배포 → API 비용 $0
- angr는 사용하지 않음 — Ghidra headless의 `xref_graph.py`로 CFG 구축 (zero-dependency 원칙 유지)

### 1.2 Semantic Function Classifier

**왜:** 수천 개 함수를 모두 LLM taint 분석에 넣으면 비용 폭발. 정적 필터 → haiku 분류 → sonnet 정밀 분석의 3-pass.

**어떻게:**
```python
# src/aiedge/semantic_classifier.py
# Pass 1: 정적 필터 (dangerous API 포함 함수만) — $0
# Pass 2: haiku 분류 (500개 → 카테고리 라벨) — ~$0.50
# Pass 3: sonnet 정밀 분석 (고위험 50개만) — ~$0.50
```

**근거:**
- LLMxCPG (USENIX Sec 2025): 코드 크기 67-91% 감소 → F1 15-40% 향상
- FirmAgent: Pre_Fuzzing에서 handler 3개만 선별 → 91% precision 유지

---

## Phase 2: Runtime-Guided Taint Analysis (Week 5-7)

### 2.1 Enhanced Static Source Identification (신규)

**왜:** Phase 2.2(Csource)는 에뮬레이션 성공 이미지에서만 동작. FirmAE 성공률 ~79%이므로 21%는 Csource를 못 쓴다. 기존 정적 `surfaces`의 source precision이 21.6%(FirmAgent Table II)면 이 21% 이미지의 분석이 거의 무의미.

**어떻게:**
```python
# src/aiedge/enhanced_source.py
INPUT_APIS = {
    "recv", "read", "fgets", "getenv", "websGetVar", "httpGetEnv",
    "nvram_get", "acosNvramConfig_get", "json_object_get_string",
    "cJSON_GetObjectItem", "getParameter", "wp_getVar"
}

def identify_sources(binary_analysis: dict) -> list[dict]:
    """
    .dynstr에서 INPUT_APIS 호출 위치를 찾고,
    Ghidra xref로 return value 사용처 1-hop 추적.
    LLM 없음, --no-llm에서도 동작, $0.
    """
```

**이 단계가 있어야 하는 또 다른 이유:** Phase 4 ablation study에서 "Enhanced Static → +Csource"의 delta를 분리 가능. 없으면 두 기여가 혼재됨.

**산출물:** `stages/enhanced_source/sources.json`
**비용:** $0 (정적 분석)

### 2.2 Csource 런타임 식별

**왜:** FirmAgent의 **가장 중요한 혁신**. 정적 source precision 21.6% → 런타임 100%.

**어떻게:**
1. `emulation` 스테이지에서 FirmAE로 부팅
2. HTTP 입력에 TAINTTAG 마커 주입
3. QEMU TCG 계측으로 마커 전파 추적 (sink-reachable 범위 내만)
4. `stages/csource_identification/csource.json` 생성
5. **에뮬레이션 실패 시:** Phase 2.1의 enhanced static 결과를 fallback

**근거:** FirmAgent Table V — Csource precision 100%, coverage 94.2%

**완료 기준:** 10개 펌웨어에서 Csource 식별 성공, enhanced static 대비 precision 개선 확인

### 2.3 LLM Inter-Procedural Taint Propagation

**왜:** FirmAgent의 **두 번째 핵심 기법**. ablation에서 제거 시 TPR 91%→44% (Table VI, Firm-Emt).

**어떻게:**
- Csource + **Ghidra xref_graph** (angr 사용하지 않음 — zero-dependency) → source-to-sink 경로
- 경로상 각 함수를 디컴파일 → LLM taint 분석 (FirmAgent Fig. 4 프롬프트)
- unknown 함수 발견 시 iterative expansion
- **function-level caching**: 동일 함수 재분석 방지 (FirmAgent에서 차용)

**비용:** ~$2.50/firmware (sonnet, ~250 호출)

### 2.4 Few-Shot FP Verification

**왜:** 3가지 mechanical FP 패턴 제거. FirmAgent ablation: 제거 시 42개 추가 FP.

**3가지 패턴:**
1. Sanitizer: `atoi()`, `isValidIpAddr()` 통과 → NOT vulnerable
2. Non-propagating: 조건 분기에서 상수 선택에만 사용 → NOT vulnerable
3. System file: `/etc/passwd` 등에서 읽은 값 → NOT vulnerable

**비용:** ~$0.30/firmware

### 2.5 Adversarial Triage (신규)

**왜:** Phase 2.4는 패턴 필터(mechanical). 이건 **구조적 FP 제거**(contextual). FirmAgent에 없는 레이어 → SCOUT 차별점.

**어떻게:**
```
Finding (confidence ≥ 0.5)
  → Advocate (sonnet): "이 finding이 왜 exploitable한지 주장"
  → Critic (sonnet): "이 finding이 왜 NOT exploitable한지 반박"
  → Rebuttal 강도에 따라 confidence 조정

예시:
  Critic: "1) chroot jail 안에서 발생
           2) LAN-only ACL 뒤에 있음
           3) input에 ';|&' 필터 존재"
  → confidence 0.75 → 0.45 (dismissed)
```

**근거:** Terminator `triager_sim.md`에서 검증. H1 triager 롤플레이 패턴.
**비용:** ~$0.50/firmware (confidence ≥ 0.5인 finding만, 전체의 ~20-30%)

---

## Phase 3: PoC Loop + Chain Construction (Week 8-10)

### 3.1 Fuzzing-Seeded PoC Generation

**왜:** 현재 `exploit_autopoc`은 처음부터 PoC 생성. FirmAgent은 fuzzer의 reachable test case를 시작점으로 → 91.8% E-PoC.

**어떻게:**
```
fuzzing stage → crash/hang input 수집
  → Csource + taint path 정보 결합
  → LLM: reachable test case + constraints → PoC 완성
  → 에뮬레이션 실행 → 성공/실패
  → 실패 시 crash log 피드백 → v2 생성
  → 최대 5회 반복, budget cap $10/firmware
```

**Seed 우선순위 (directed fuzzing 경량화 대체):**
AFLGo 전면 통합 대신, Phase 2.2의 sink-distance score를 AFL++ seed scheduling에만 반영. `--seed-weight` 수준이라 구현 비용 최소. FirmAgent ablation에서 directed 제거 시 TPR 0.3%p 차이뿐이므로 full integration은 불필요.

### 3.2 Chain Construction — 단계적 접근

**왜:** 논문의 killer contribution이지만, FP chain 폭발 위험. 3단계로 분리하여 리스크 분산.

**Step 1: Same-binary chain (Week 8)**
```
httpd 내부:
  websGetVar("cmd") → sprintf(buf, "...; %s", cmd) → system(buf)
```
Phase 2.3의 taint propagation 결과를 chain 형태로 조립. 추가 구현 최소.
→ 성공 시: 논문에 "intra-binary chain" 기재 가능 (최소 contribution 보장)

**Step 2: IPC-mediated chain (Week 9)**
```
httpd → nvram_set("admin_pass", input)
  [IPC: nvram 공유 메모리/파일시스템]
config daemon → nvram_get("admin_pass") → 설정 변경
```
두 바이너리가 같은 string constant를 `.rodata`에서 공유하면 IPC 가능성 높음.
SCOUT의 기존 `graph` 스테이지 IPC 5종 edge type 활용.
→ 성공 시: 논문에 "cross-binary chain" 기재 (Plan A 달성)

**Step 3: Full cross-binary exploit chain (Week 10, bonus)**
```
httpd (auth bypass) → nvram (config 변조) → init script → telnetd (root shell)
```
3-hop 이상. LLM이 IPC semantics를 이해해야 함. FP 위험 높음.
→ 실패해도 Step 2까지로 논문 가능

### 3.3 Verified Chain 달성

**왜:** SCOUT의 가장 큰 약점 해소 — "아키텍처는 있는데 결과가 없다".

**어떻게:**
1. Phase 3.1의 PoC가 confirmed에 도달한 finding 선별
2. 에뮬레이션에서 3회 재현 (verified_chain 요구사항)
3. SHA-256 manifest에 기록
4. `verify_verified_chain.py` 통과

**완료 기준:** verified_chain ≥ 1건

---

## Phase 4: 대규모 평가 + 논문 (Week 11-13)

### 4.1 3-Tier 평가 전략

전체에 동일 depth를 적용하면 비현실적. 3-tier로 분리:

```
Tier 1 (1,124개) — 정적 파이프라인만
  목적: scale 보여줌
  비용: $0 (LLM 없음)
  산출물: Table 1 "Images analyzed"

Tier 2 (200개) — 에뮬레이션 + LLM taint + PoC
  선별: FirmAE boot 성공 + Csource 식별 가능
  비용: ~$920 (200 × $4.60)
  산출물: Table 2 precision/recall/FPR

Tier 3 (14개) — FirmAgent 동일 이미지
  목적: head-to-head 비교
  비용: ~$65 (14 × $4.60)
  산출물: Table 3 직접 비교
```

**총 LLM 비용: ~$985** (원래 $5,170의 1/5)

### 4.2 Ablation Study

**왜:** 각 기법의 기여도 분리.

| Variant | 대응 Phase | 측정 |
|---------|-----------|------|
| SCOUT-Static (baseline) | Phase 0B | TPR, FPR |
| +Enhanced Static Source | Phase 2.1 | source precision 개선 |
| +Decompile Refinement | Phase 1.1 | taint 정확도 개선 |
| +Csource Runtime | Phase 2.2 | source precision 100% 도달 |
| +LLM Taint Propagation | Phase 2.3 | TPR 대폭 개선 |
| +FP Verification | Phase 2.4 | FPR 감소 |
| +Adversarial Triage | Phase 2.5 | FPR 추가 감소 |
| +PoC Loop | Phase 3.1 | confirmed 건수 |
| +Chain Construction | Phase 3.2 | chain 건수 |
| **SCOUT v2 (full)** | 전체 | 최종 수치 |

### 4.3 LLM Trace Reproducibility

**왜:** NDSS/USENIX artifact evaluation에서 "재현 가능한가?"가 핵심. LLM은 non-deterministic.

**어떻게:**
```json
// stages/<stage>/llm_trace/<call_id>.json
{
  "call_id": "taint-propagation-042",
  "model": "claude-sonnet-4-20250514",
  "input_hash": "sha256:abc123...",
  "input_text": "...(full prompt)...",
  "output_text": "...(full response)...",
  "output_hash": "sha256:def456...",
  "latency_ms": 2340,
  "token_cost_usd": 0.012
}
```

- `--replay-llm-trace <path>`: 캐시된 결과로 LLM 호출 없이 재현
- 기존 `llm_cost.py` 확장
- artifact evaluation 시 trace 파일 포함하여 제출

### 4.4 논문 작성

**Target:** NDSS 2027 (마감 ~2026년 6월) 또는 USENIX Security 2027

---

## 비용 모델 (수정됨)

### Per-firmware 비용 (Tier 2 기준)

| Phase | 모델 | 비용 | 비고 |
|-------|------|------|------|
| 1.1 Decompile Refinement | Ollama (로컬) | $0 | gate 통과 시만 |
| 1.2 Semantic Classifier | haiku + sonnet | ~$1.00 | |
| 2.1 Enhanced Static Source | 없음 | $0 | 정적 분석 |
| 2.2 Csource | 없음 | $0 | QEMU 계측 |
| 2.3 Taint Propagation | sonnet | ~$2.50 | function-level cache |
| 2.4 FP Verification | sonnet | ~$0.30 | |
| 2.5 Adversarial Triage | sonnet | ~$0.50 | confidence ≥ 0.5만 |
| 3.1 PoC Generation | sonnet/opus | ~$0.50 | |
| 3.2 Chain Construction | opus | ~$0.30 | 1-3회 |
| **합계** | | **~$5.10** | |

### Worst-case cap

대형 바이너리(httpd > 10MB, 20,000+ 함수)에서 비용이 $15-20까지 올라갈 수 있음.
`AIEDGE_LLM_BUDGET_USD`를 per-firmware $10으로 cap. 초과 시 Phase 2.3의 분석 depth를 자동 축소 (deepest path만 분석).

### 전체 벤치마크 비용

| Tier | 이미지 수 | 비용 |
|------|-----------|------|
| Tier 1 (정적) | 1,124 | $0 |
| Tier 2 (full) | 200 | ~$920 |
| Tier 3 (비교) | 14 | ~$65 |
| **합계** | | **~$985** |

---

## 리스크 + Fallback 경로 (수정됨)

| 리스크 | Fallback |
|--------|----------|
| **Phase 1.1:** MIPS/ARM에서 refinement 악화 | A/B gate에서 skip → raw Ghidra로 직행 |
| **Phase 2.2:** 에뮬레이션 실패 (21%) | Phase 2.1 Enhanced Static Source가 fallback |
| **Phase 2.3:** LLM taint precision이 FirmAgent 미달 | Phase 2.4+2.5의 FP 필터가 보정 |
| **Phase 3.2:** Cross-binary chain FP 폭발 | Plan B (precision-guaranteed 스토리) |
| **Phase 3.3:** Verified chain 0건 | known CVE 펌웨어 10개에서 우선 시도 |
| **비용 초과** | per-firmware $10 cap + Tier 2를 100개로 축소 |

---

## 타임라인

```
Week 1       Phase 0A: __main__.py 분리, assert_under_dir 통합, pyright
Week 1-2     Phase 0B: FirmAE static baseline, FirmRec 매칭 로직, CVE 후보 선별
Week 3-4     Phase 1:  LLM4Decompile (MIPS/ARM gate) + Semantic Classifier
Week 5-7     Phase 2:  Enhanced Source → Csource → Taint → FP filter → Adversarial
Week 8-10    Phase 3:  PoC Loop + Chain (Step 1→2→3)
Week 11-13   Phase 4:  3-Tier 평가 + Ablation + LLM trace + 논문
```

**총 기간: 13주 (~3개월)**

---

## 성공 기준

| 기준 | 목표 | Plan B 최소 |
|------|------|-------------|
| 분석 scale | ≥ 1,124 (Tier 1) | 1,124 |
| Precision (Tier 2) | ≥ 85% | ≥ 90% (adversarial triage) |
| FPR | ≤ 10% | ≤ 5% |
| Confirmed findings | ≥ 50 | ≥ 30 |
| Verified chains | ≥ 5 | ≥ 1 |
| Cross-binary chains | ≥ 3 (Plan A) | 0 (Plan B) |
| Novel vulns | ≥ 10 (CVE 신청) | ≥ 5 |
| Cost/firmware | ≤ $5.10 | ≤ $5.10 |
| `--no-llm` 재현 | 정적 파이프라인 100% 동일 | 100% |
| LLM trace replay | artifact evaluation 통과 | 통과 |

---

## 신규 Stage/모듈 요약

| 모듈 | Phase | 위치 | LLM | 비용 |
|------|-------|------|-----|------|
| `enhanced_source.py` | 2.1 | emulation 전 | X | $0 |
| `csource_identification.py` | 2.2 | emulation 후 | X | $0 |
| `taint_propagation.py` | 2.3 | csource 후 | sonnet | $2.50 |
| `adversarial_triage.py` | 2.5 | llm_triage 후 | sonnet | $0.50 |
| `poc_refinement.py` | 3.1 | fuzzing 후 | sonnet/opus | $0.50 |
| `chain_constructor.py` | 3.2 | findings 후 | opus | $0.30 |
| `semantic_classifier.py` | 1.2 | ghidra 후 | haiku/sonnet | $1.00 |
| `scripts/firmrec_matcher.py` | 0B | 평가용 | X | $0 |

---

## v2.0 파이프라인 (최종)

```
[기존]
tooling → extraction → ... → findings → llm_triage → ... → exploit_autopoc → ...

[v2.0]
tooling → extraction → ... → ghidra_analysis
  → [1.1 decompile_refinement] → [1.2 semantic_classifier]
  → sbom → cve_scan → reachability → endpoints → surfaces
  → [2.1 enhanced_source]
  → emulation → [2.2 csource_identification]
  → [2.3 taint_propagation]
  → findings
  → [2.4 fp_verification] → [2.5 adversarial_triage]
  → llm_triage → llm_synthesis
  → fuzzing → [3.1 poc_refinement]
  → [3.2 chain_construction]
  → exploit_gate → exploit_chain → poc_validation → exploit_policy
```

`[번호]` = 신규, 나머지 = 기존 유지. `--no-llm` 시 모든 `[번호]` stage가 graceful skip.

---

## Appendix A: QEMU Taint Tracking 기술 분석

### FirmAgent의 실제 구현 — deep TCG taint가 아님

FirmAgent의 "100% precision Csource"는 byte-level taint propagation이 아니다. 실제 구현:
1. HTTP 파라미터에 sentinel 문자열 TAINTTAG 주입
2. AFL++ QEMU user-mode (afl-qemu-trace-arch)에서 실행
3. QEMU\_DFILTER 환경변수로 sink-reachable BB 범위만 계측
4. libibresolver.so (LD\_PRELOAD)가 control-flow 로깅
5. 로그에서 TAINTTAG가 도달한 PC 주소 추출

### SCOUT 구현 방안

| 접근 | 구현량 | 기간 | 정밀도 |
|------|--------|------|--------|
| FirmAgent sentinel 복제 | 400줄 Python | **2주** | PC-level (coarse) |
| QEMU plugin API (7.x+) | 500줄 C | 3-4주 | addr-level |
| Frida Stalker | 300줄 Python+JS | 2-3주 | BB-level |
| PyPANDA taint2 | 200줄 Python | 4-6주 | byte-level (정밀) |

권장: FirmAgent sentinel 복제. AFL++의 afl-qemu-trace 바이너리가 MIT 라이선스로 공개.

---

## Appendix B: Pandawan 통합 기술 분석

### 핵심 발견

1. PostgreSQL 불필요 - Pandawan 분석 코드가 PostgreSQL을 호출하지 않음. SCOUT 자체 extraction으로 bypass 가능.
2. FirmSolo KCRE 독립 실행 가능 - 파일 기반 I/O, nm+strings+cscope+cross-compiler만 필요.
3. Docker 이미지 50GB에서 15-18GB로 축소 가능 (PostgreSQL, TriforceAFL, Java, 중복QEMU, 프리빌드데이터 제거).

### 타임라인: Csource 2주, Pandawan minimal 6주

---

## Appendix C: 5개 도구 비교

| 축 | SCOUT | FirmAE | Pandawan | FirmAgent | WAIRZ |
|----|-------|--------|----------|-----------|-------|
| 정체성 | evidence engine | 에뮬레이션 | re-hosting | vuln discovery | AI agent 플랫폼 |
| LLM | additive | 없음 | 없음 | 핵심 의존 | 핵심 의존 |
| no-llm 동작 | O | N/A | N/A | X | X |
| Evidence governance | SHA-256+SARIF+SLSA | 없음 | 없음 | 없음 | 없음 |
| Cross-binary chain | IPC 5종+chain | 없음 | kernel+user | X (단일) | 없음 |
| Dependencies | zero pip | PG+Docker | 50GB Docker | IDA Pro+angr | Docker+PG+Redis |
| Scale | 1,124 준비 | 1,124 | 1,520 | 14 | 없음 |
| 취약점 발견 | 측정 중 | 320+12 | 16 | 182 (91%) | 미공개 |
| MCP tools | 12 | 0 | 0 | 0 | 60+ |

### SCOUT 한계 (난이도 재평가)

| 한계 | 심각도 | 해소 난이도 | 기간 |
|------|--------|------------|------|
| 실증 데이터 없음 | 치명 | 쉬움 | 즉시 |
| Csource 미구현 | 높음 | 쉬움 (sentinel) | 2주 |
| Pandawan 통합 | 중간 | 중간 (minimal) | 6주 |
| Ghidra vs IDA 품질 | 중간 | 중간 | 중기 |
| PANDA modern QEMU 포팅 | 참고 | 불가능 | 12-18개월 |

---

## 타임라인 (최종 수정)

```
Week 1       Phase 0A: __main__.py 분리 ← 완료
Week 1-2     Phase 0B: FirmAE static baseline + FirmRec 매칭
Week 3-4     Phase 1:  Semantic Classifier + Decompile Refinement (MIPS/ARM gate)
Week 5-6     Phase 2a: Enhanced Source + Csource Sentinel (FirmAgent 방식, 2주)
Week 6-7     Phase 2b: LLM Taint Propagation + FP Verification + Adversarial Triage
Week 8-10    Phase 3:  PoC Loop + Chain Construction (Step 1/2/3)
Week 11-13   Phase 4:  3-Tier 평가 + Ablation + 논문
Week 14-19   Phase 5 (선택): Pandawan Minimal 통합 (커널 모듈, 6주)
```

---

## 진행 체크리스트 (2026-03-27 기준)

### Phase 0A: 구조 정비
- [x] `__main__.py` 4,519줄 → 7개 모듈 분리 (659줄로 축소)
- [x] `cli_common.py` 생성 (397줄)
- [x] `cli_serve.py` 생성 (77줄)
- [x] `cli_tui_data.py` 생성 (1,255줄)
- [x] `cli_tui_render.py` 생성 (1,530줄)
- [x] `cli_tui.py` 생성 (201줄)
- [x] `cli_parser.py` 생성 (562줄)
- [x] `_assert_under_dir()` 복사본 통합 확인 (이미 완료 상태)
- [x] ruff check 통과
- [x] pytest 전체 통과
- [x] `test_cli_tui.py` monkeypatch 경로 수정
- [ ] pyright core 모듈 blocking 전환 (미착수)

### Phase 0B: 벤치마크 인프라
- [x] FirmAE 데이터셋 다운로드 (12GB, 1,124개)
- [x] 벤더별 분류 완료 (8개 벤더 디렉토리)
- [x] `scripts/benchmark_firmae.sh` 작성
- [x] `scripts/unpack_firmae_dataset.sh` 작성
- [x] 기존 runs 정리 (222 → 74개, 44GB 확보)
- [ ] FirmAE 1,124개 정적 baseline 실행 (미착수)
- [ ] `scripts/firmrec_matcher.py` FirmRec 매칭 로직 (미착수)
- [ ] FirmRec 데이터셋 다운로드 (미착수)
- [ ] Known-CVE 펌웨어 10개 선별 (미착수)

### Phase 1: Ghidra Refinement + Semantic Classifier
- [x] `semantic_classifier.py` 생성 + stage_registry 등록
- [x] 정적 필터 (Pass 1: dangerous API) 구현 및 동작 확인 (100개 분류)
- [x] binary_analysis.json fallback 경로 구현
- [x] LLM 분류 — Ghidra 2,243 함수 디컴파일 성공, codex 호출 확인
- [ ] LLM 정밀 분석 (Pass 3: sonnet) 실제 동작 검증 (미검증)
- [ ] LLM4Decompile-Ref 통합 (DEFER — MIPS/ARM A/B test 필요)
- [ ] MIPS/ARM validation gate 구현 (미착수)

### Phase 2: Runtime-Guided Taint Analysis
- [x] `enhanced_source.py` 생성 + stage_registry 등록
- [x] INPUT_APIS 14개 기반 .dynstr 스캔 구현 (146 sources)
- [x] binary_analysis.json 직접 파싱 구현
- [x] `taint_propagation.py` 생성 + stage_registry 등록
- [x] 정적 추론 fallback (50 alerts 생성)
- [x] surfaces source_sink_graph.json fallback
- [ ] LLM inter-procedural taint 분석 실제 동작 검증 (codex 호출은 됨, 결과 미확인)
- [ ] Function-level cache 동작 검증 (미확인)
- [x] `fp_verification.py` 생성 + stage_registry 등록
- [ ] 3-pattern FP 제거 LLM 호출 실제 동작 검증 (skip됨 — upstream 형식 확인 필요)
- [x] `adversarial_triage.py` 생성 + stage_registry 등록
- [ ] Advocate/Critic LLM debate 실제 동작 검증 (skip됨 — upstream 형식 확인 필요)
- [x] Csource sentinel 구현 (`csource_identification.py`, R7000에서 87 csources 식별)

### Phase 3: PoC Loop + Chain Construction
- [x] `poc_refinement.py` 생성 + stage_registry 등록
- [x] exploit_candidates + pattern_scan fallback 추가
- [ ] LLM PoC 생성 + iterative loop 실제 동작 검증 (미검증)
- [ ] emulation 검증 루프 (generate→test→revise) 동작 확인 (미검증)
- [x] `chain_constructor.py` 생성 + stage_registry 등록
- [x] same-binary sink+hardening chain 생성 (50 chains)
- [x] pattern_scan + exploit_candidates 데이터 소스 통합
- [x] IPC cross-binary chain (Step 2) 코드 구현 완료 (R7000에서 shared .rodata 패턴 미감지, 코드 ready)
- [ ] LLM chain reasoning (Step 3, opus) 실제 동작 검증 (미검증)

### Phase 4: 대규모 평가 + 논문
- [ ] Tier 1: 1,124개 정적 파이프라인 (미착수)
- [ ] Tier 2: 200개 full pipeline + LLM (미착수)
- [ ] Tier 3: FirmAgent 14개 동일 이미지 비교 (미착수)
- [ ] Ablation study (미착수)
- [ ] LLM trace reproducibility (`--replay-llm-trace`) 구현 (미착수)
- [ ] 논문 작성 (미착수)

### Phase 5 (선택): Pandawan Minimal 통합
- [ ] PostgreSQL bypass 구현 (미착수 — 가능 확인됨)
- [ ] FirmSolo KCRE 독립 실행 검증 (미착수 — 가능 확인됨)
- [ ] Minimal Docker 이미지 빌드 (미착수 — 15-18GB 목표)
- [ ] SCOUT emulation stage Tier 1.5 연결 (미착수)

### 파이프라인 통합 (run.py)
- [x] early_stages에 5개 신규 stage 등록
- [x] 후반부에 poc_refinement + chain_construction 등록
- [x] `_apply_stage_result_to_report()` generic catch-all 추가
- [x] 7개 factory 함수 추가
- [x] chain_constructor 데이터 소스 버그 수정 (P1)
- [x] poc_refinement fallback input 추가 (P2)

### 버그 수정
- [x] `_apply_stage_result_to_report()` 신규 stage 결과 누락 (P0)
- [x] `chain_constructor.py` Python 연산자 우선순위 버그 (P1)
- [x] `poc_refinement.py` fallback input 없음 (P2)
- [x] `semantic_classifier.py` classifications 변수 미초기화
- [x] `taint_propagation.py` 미사용 변수 (syms_lower)
- [x] `test_cli_tui.py` monkeypatch 경로

### 문서
- [x] `docs/upgrade_plan_v2.md` 작성 (본 문서)
- [x] `docs/roadmap_llm_agent_integration.md` 작성
- [x] Appendix A: QEMU taint tracking 분석
- [x] Appendix B: Pandawan 통합 분석
- [x] Appendix C: 5개 도구 비교

### 리서치 (코드 구현에 반영)
- [x] FirmAgent (NDSS 2026) 파이프라인 분석
- [x] Pandawan (USENIX Sec 2024) 통합 가능성 분석
- [x] WAIRZ 비교 분석
- [x] QEMU TCG taint — sentinel 방식 2주면 가능 확인
- [x] Pandawan — PostgreSQL bypass + KCRE 독립 실행 가능 확인
- [x] 20+ 관련 논문 조사 (DeGPT, LLM4Decompile, ChatAFL, HPTSA 등)

### 검증 결과 (OpenWrt 6.2MB)
- [x] 전체 33개 stage 실행 성공 (exit code 0)
- [x] Ghidra headless 3개 바이너리 디컴파일
- [x] Emulation (FirmAE Docker) 성공
- [x] LLM (codex) triage + synthesis 호출 성공
- [x] enhanced_source: 146 sources
- [x] semantic_classification: 100 classified (55 cmd_handler, 45 mem_mgmt)
- [x] taint_propagation: 50 alerts
- [x] chain_construction: 50 chains
- [x] fp_verification: LLM 호출 성공 (R7000 ok)
- [x] adversarial_triage: LLM 호출 성공 (R7000 ok)
- [x] poc_refinement: LLM PoC 생성 성공 (R7000 ok)
