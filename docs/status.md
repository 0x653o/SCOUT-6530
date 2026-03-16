# Status

이 문서는 "현재 구현 상태"를 솔직하게 기록합니다.

## 현재 구현됨

- AIEdge CLI: `./scout analyze`, `./scout stages` (래퍼 권장)
- 동일 기능은 `python3 -m aiedge analyze`, `python3 -m aiedge stages`로 직접 실행 가능
- Stage evidence store(run_dir): StageFactory stage는 `stages/<name>/stage.json` 기반 artifact hashing을 사용하고, findings는 `run_findings()`가 `stages/findings/*.json`을 직접 생성
- `analyze`/`analyze-8mb`에 `--rootfs <DIR>` 지원 (사전 추출 rootfs 직접 ingest)
- `firmware_profile` stage:
  - `stages/firmware_profile/stage.json`과 `stages/firmware_profile/firmware_profile.json` 생성이 확인됨
  - ELF 교차검증(`arch_guess`, `elf_hints`)으로 OS/arch 오탐 완화
- Inventory stage는 "죽지 않고" `inventory.json`/`string_hits.json`/`binary_analysis.json`을 남김
- extraction/inventory 품질 게이트(coverage threshold) 반영:
  - sparse 결과는 `quality.status=insufficient`로 표시되고 `partial`로 강등될 수 있음
- `firmware_handoff.json` 자동 생성 (analyze + stages)
- TUI/뷰어 진입 가이드는 `./scout tui` 단축키(`ti/tw/to`) 및 `./scout serve`를 기준으로 정렬되어 최신 상태입니다.
- SquashFS 재귀 추출: BFS 큐 기반, 깊이 제한 4, 오프셋 기반 매직 스캔(벤더 래퍼 대응). 이중/다중 SquashFS 자동 추출 가능.
- 심링크 containment: 추출된 심링크가 `run_dir` 밖으로 resolve되면 rootfs 후보에서 제외. `_rel_to_run_dir`, `_probe_is_dir`, `_probe_exists`, `_resolve_or_record`, `is_dir_safe`, `is_file_safe` 모두 적용.
- `_BINARY_BRIDGE_TOKENS` 탐지 카테고리: `sprintf`/`snprintf`/`strcat`/`strcpy` 등이 `system`/`popen` exec 싱크 근처에 있으면 커맨드 인젝션 브릿지로 플래그. inventory 교차검증(`bridge_sink_cooccurrence`) 포함.
- `web_ui` 스테이지: HTML/JS 보안 패턴 스캐너. `stages/web_ui/web_ui.json` 산출. JS 9개 패턴 + HTML 4개 패턴 + API 스펙 파일 탐지.
- LLM Provider 추상화: `llm_driver.py` (LLMDriver Protocol, CodexCLIDriver, `resolve_driver()`). 3개 호출사이트(llm_synthesis, exploit_autopoc, llm_codex) 통합. `AIEDGE_LLM_DRIVER` env var로 provider 선택, ModelTier ("haiku"|"sonnet"|"opus") 지원.
- 바이너리 하드닝: 순수 Python ELF 파서로 NX/PIE/RELRO/Canary/Stripped 수집. inventory `binary_analysis.json`에 `hardening_summary` 포함. findings 점수에 하드닝 기반 보정 적용 (fully hardened: x0.7, no protection: x1.15).
- 3-Tier 에뮬레이션: FirmAE Docker 이미지(Tier 1) + QEMU user-mode 서비스 프로빙(Tier 2, lighttpd/busybox/dnsmasq/sshd) + rootfs 검사 fallback(Tier 3). `docker/scout-emulation/` Dockerfile 포함. `AIEDGE_EMULATION_IMAGE`, `AIEDGE_FIRMAE_ROOT` env var.
- 엔디안 인식 아키텍처 감지: MIPS/ARM 빅/리틀엔디안 정확 구분 (`mips_be`, `mips_le`, `arm_be`, `arm_le`).
- 취약점 유형별 PoC 템플릿: `poc_templates.py` 레지스트리 4종 (cmd_injection, path_traversal, auth_bypass, info_disclosure) + tcp_banner fallback. `poc_skeletons/` 디렉토리에 standalone PoC 파일.
- exploit_runner 실제 PCAP 캡처: tcpdump 가용 시 실제 패킷 캡처 (기존 placeholder fallback 유지).
- PoC 재현성 검증: `poc_validation`에서 readback_hash 일관성 확인으로 재현성 보장.
- LLM 트리아지 스테이지: findings → `llm_triage` → llm_synthesis 순서로 실행. 모델 티어 자동 선택 (<10: haiku, 10-50: sonnet, >50: opus). 하드닝/attack_surface 보안 컨텍스트 포함 프롬프트. `--no-llm`에서 graceful skip.
- Terminator 양방향 피드백 루프: `terminator_feedback.py`가 `firmware_handoff.json`에 `feedback_request` 섹션 추가. Terminator 판정(confirmed boost, false_positive suppress)이 `duplicate_gate`에 반영. `AIEDGE_FEEDBACK_DIR` env var.

## Known Issues (중요)

- 샌드박스/호스트 정책에 따라 `serve --once`가 포트 바인딩 권한 문제로 실패할 수 있음 (`Operation not permitted`).
- 다층 벤더 포맷은 재귀 SquashFS로 많이 개선되었으나, 암호화된 포맷이나 특수 커스텀 헤더는 여전히 수동 추출 필요.
  - 현재는 `--rootfs` 우회가 보완 경로이며, 포맷 전용 extractor 체인 확장은 계속 필요.
- 바이너리 보안 속성(NX/PIE/RELRO/Canary)이 순수 Python으로 수집되며 findings 점수에 반영. 디컴파일/CFG 기반 정밀 분석 통합은 미완.

## 다음 우선순위

1) 벤더 포맷 전용 extraction chain 확장 (QNAP/Synology/ASUS 계열 깊은 중첩 포맷)
2) 바이너리 심층 분석: checksec 수준은 통합 완료. Ghidra headless 디컴파일 + LLM 분석 연계가 다음 목표
3) FirmAE 호환 펌웨어 커버리지 확대 (Tier 1 에뮬레이션 성공률 향상)
4) (오케스트레이터 레이어) tribunal/judge + validator evidence를 통한 confirmed 승격 정책 E2E 강화
