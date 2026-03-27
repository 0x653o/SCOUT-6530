from __future__ import annotations

"""Adversarial triage stage.

Uses an Advocate/Critic LLM debate pattern to reduce false-positive rate
by having two opposing perspectives argue exploitability for each finding.
Skips under ``--no-llm``.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .llm_driver import resolve_driver
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "adversarial-triage-v1"
_LLM_TIMEOUT_S = 120.0
_LLM_MAX_ATTEMPTS = 3
_RETRYABLE_TOKENS: tuple[str, ...] = (
    "stream disconnected",
    "error sending request",
    "connection reset",
    "connection refused",
    "timed out",
    "timeout",
    "temporary failure",
    "503",
    "502",
    "429",
)

_CONFIDENCE_REDUCTION = 0.2

# Mitigations the critic may cite as strong rebuttals
_STRONG_MITIGATIONS: frozenset[str] = frozenset({
    "chroot",
    "acl",
    "input filter",
    "input validation",
    "seccomp",
    "apparmor",
    "selinux",
    "sandboxing",
    "sandbox",
    "rate limit",
    "authentication required",
    "authorization check",
    "canary",
    "stack protector",
    "aslr",
    "nx bit",
    "pie",
})


def _load_json_file(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _build_advocate_prompt(finding: dict[str, object]) -> str:
    finding_json = json.dumps(finding, indent=2, ensure_ascii=True)
    return (
        "You are an offensive security researcher acting as an ADVOCATE.\n"
        "Your job is to argue why the following firmware finding IS\n"
        "exploitable. Cite specific evidence from the finding data.\n\n"
        "## Finding\n"
        f"{finding_json}\n\n"
        "## Rules\n"
        "- Focus on attacker-reachable input paths\n"
        "- Consider lack of input validation or sanitization\n"
        "- Note missing hardening (no PIE, no canary, no NX)\n"
        "- Consider chain potential with other vulnerabilities\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "exploitable": true,\n'
        '  "argument": "<detailed argument>",\n'
        '  "evidence_cited": ["<specific evidence points>"],\n'
        '  "attack_scenario": "<brief attack scenario>"\n'
        "}\n"
    )


def _build_critic_prompt(
    finding: dict[str, object], advocate_argument: str,
) -> str:
    finding_json = json.dumps(finding, indent=2, ensure_ascii=True)
    return (
        "You are a defensive security engineer acting as a CRITIC.\n"
        "Your job is to argue why the following firmware finding is NOT\n"
        "exploitable. Consider mitigations, hardening, and practical\n"
        "barriers to exploitation.\n\n"
        "## Finding\n"
        f"{finding_json}\n\n"
        "## Advocate's Argument (opposing view)\n"
        f"{advocate_argument}\n\n"
        "## Rules\n"
        "- Consider specific mitigations: chroot, ACL, input filters,\n"
        "  seccomp, AppArmor, SELinux, sandboxing\n"
        "- Note binary hardening: canaries, ASLR, NX, PIE\n"
        "- Consider authentication/authorization requirements\n"
        "- Identify practical exploitation barriers\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "exploitable": false,\n'
        '  "rebuttal": "<detailed rebuttal>",\n'
        '  "mitigations_cited": ["<specific mitigations>"],\n'
        '  "exploitation_barriers": ["<practical barriers>"]\n'
        "}\n"
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    text = stdout.strip()
    if not text:
        return None
    fences = re.findall(
        r"```(?:json)?\s*\n(.*?)```",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    for fence in fences:
        try:
            obj = json.loads(fence)
            if isinstance(obj, dict):
                return cast(dict[str, object], obj)
        except (json.JSONDecodeError, ValueError):
            continue
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return cast(dict[str, object], obj)
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _has_strong_rebuttal(critic_response: dict[str, object]) -> bool:
    """Check if critic cited specific strong mitigations."""
    mitigations = critic_response.get("mitigations_cited", [])
    if not isinstance(mitigations, list):
        return False
    for mit in cast(list[object], mitigations):
        if isinstance(mit, str):
            mit_lower = mit.lower()
            for strong in _STRONG_MITIGATIONS:
                if strong in mit_lower:
                    return True

    barriers = critic_response.get("exploitation_barriers", [])
    if isinstance(barriers, list):
        for barrier in cast(list[object], barriers):
            if isinstance(barrier, str):
                barrier_lower = barrier.lower()
                for strong in _STRONG_MITIGATIONS:
                    if strong in barrier_lower:
                        return True
    return False


@dataclass(frozen=True)
class AdversarialTriageStage:
    """Advocate/Critic debate to reduce FPR."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "adversarial_triage"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "adversarial_triage"
        out_json = stage_dir / "triaged_findings.json"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)

        limitations: list[str] = []

        # --- Skip under --no-llm ---
        if self.no_llm:
            payload: dict[str, JsonValue] = {
                "schema_version": _SCHEMA_VERSION,
                "status": "skipped",
                "reason": "no_llm_mode",
                "triaged_findings": [],
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details=cast(dict[str, JsonValue], {"reason": "no_llm_mode"}),
                limitations=["no_llm_mode"],
            )

        # --- Load findings from multiple fallback sources ---
        findings: list[dict[str, object]] = []

        # Try fp_verification first
        fp_path = (
            run_dir / "stages" / "fp_verification" / "verified_alerts.json"
        )
        fp_data = _load_json_file(fp_path)
        if isinstance(fp_data, dict):
            v_any = cast(dict[str, object], fp_data).get("verified_alerts")
            if isinstance(v_any, list):
                for item in cast(list[object], v_any):
                    if isinstance(item, dict):
                        findings.append(cast(dict[str, object], item))

        # Fallback 1: taint_propagation alerts
        if not findings:
            taint_path = (
                run_dir / "stages" / "taint_propagation" / "alerts.json"
            )
            t_data = _load_json_file(taint_path)
            if isinstance(t_data, dict):
                t_any = cast(dict[str, object], t_data).get("alerts")
                if isinstance(t_any, list):
                    for item in cast(list[object], t_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))
                    if findings:
                        limitations.append(
                            "Using taint_propagation alerts directly "
                            "(fp_verification unavailable)"
                        )

        # Fallback 2: findings stage
        if not findings:
            findings_path = (
                run_dir / "stages" / "findings" / "findings.json"
            )
            f_data = _load_json_file(findings_path)
            if isinstance(f_data, dict):
                f_any = cast(dict[str, object], f_data).get("findings")
                if isinstance(f_any, list):
                    for item in cast(list[object], f_any):
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, object], item))

        # Fallback 3: attack_surface entries
        if not findings:
            as_path = (
                run_dir / "stages" / "attack_surface" / "attack_surface.json"
            )
            as_data = _load_json_file(as_path)
            if isinstance(as_data, dict):
                as_entries = cast(dict[str, object], as_data).get("attack_surface")
                if isinstance(as_entries, list):
                    for entry_any in cast(list[object], as_entries):
                        if not isinstance(entry_any, dict):
                            continue
                        entry = cast(dict[str, object], entry_any)
                        conf_any = (
                            entry.get("confidence")
                            or entry.get("confidence_calibrated")
                        )
                        if isinstance(conf_any, (int, float)) and float(conf_any) > 0.3:
                            finding_entry: dict[str, object] = {
                                "source_api": str(entry.get("surface", "")),
                                "source_binary": str(
                                    entry.get("observation", "")
                                ),
                                "sink_symbol": str(
                                    entry.get("classification", "")
                                ),
                                "confidence": float(conf_any),
                                "path_description": str(
                                    entry.get("edge_semantics", "")
                                ),
                                "method": "attack_surface_fallback",
                            }
                            findings.append(finding_entry)
                    if findings:
                        limitations.append(
                            "Using attack_surface entries as fallback "
                            "(fp_verification, taint_propagation, and "
                            "findings unavailable)"
                        )

        if not findings:
            limitations.append(
                "No findings from fp_verification, taint_propagation, "
                "findings, or attack_surface stages"
            )
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "status": "partial",
                "triaged_findings": [],
                "summary": {
                    "total_input": 0,
                    "debated": 0,
                    "downgraded": 0,
                },
                "limitations": cast(
                    list[JsonValue], cast(list[object], limitations)
                ),
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], {"triaged": 0}),
                limitations=limitations,
            )

        # --- Filter findings with confidence >= 0.5 ---
        eligible = [
            f for f in findings
            if isinstance(f.get("confidence"), (int, float))
            and float(f["confidence"]) >= 0.5
        ]
        below_threshold = [
            f for f in findings
            if not isinstance(f.get("confidence"), (int, float))
            or float(f["confidence"]) < 0.5
        ]

        # --- Advocate/Critic debate ---
        driver = resolve_driver()
        triaged: list[dict[str, JsonValue]] = []
        debated_count = 0
        downgraded_count = 0

        if not driver.available():
            limitations.append("LLM driver not available for adversarial triage")
            for f in findings:
                triaged.append(cast(dict[str, JsonValue], dict(f)))
        else:
            for finding in eligible:
                finding_copy = dict(finding)

                # Advocate prompt
                advocate_prompt = _build_advocate_prompt(finding)
                advocate_result = driver.execute(
                    prompt=advocate_prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                )

                advocate_argument = ""
                advocate_parsed: dict[str, object] | None = None
                if advocate_result.status == "ok":
                    advocate_parsed = _parse_json_response(
                        advocate_result.stdout
                    )
                    if advocate_parsed is not None:
                        advocate_argument = str(
                            advocate_parsed.get("argument", "")
                        )

                # Critic prompt
                critic_prompt = _build_critic_prompt(
                    finding, advocate_argument or "(advocate failed to respond)"
                )
                critic_result = driver.execute(
                    prompt=critic_prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                )

                critic_parsed: dict[str, object] | None = None
                if critic_result.status == "ok":
                    critic_parsed = _parse_json_response(
                        critic_result.stdout
                    )

                # Compare: strong rebuttal -> reduce confidence
                if critic_parsed is not None and _has_strong_rebuttal(
                    critic_parsed
                ):
                    orig_conf = float(finding.get("confidence", 0.5))
                    new_conf = _clamp01(orig_conf - _CONFIDENCE_REDUCTION)
                    finding_copy["confidence"] = new_conf
                    finding_copy["original_confidence"] = orig_conf
                    finding_copy["triage_outcome"] = "downgraded"
                    downgraded_count += 1
                else:
                    finding_copy["triage_outcome"] = "maintained"

                # Record debate
                finding_copy["advocate_argument"] = (
                    cast(dict[str, JsonValue], advocate_parsed)
                    if advocate_parsed is not None
                    else {"error": "parse_failure"}
                )
                finding_copy["critic_rebuttal"] = (
                    cast(dict[str, JsonValue], critic_parsed)
                    if critic_parsed is not None
                    else {"error": "parse_failure"}
                )

                triaged.append(cast(dict[str, JsonValue], finding_copy))
                debated_count += 1

            # Add below-threshold findings unchanged
            for f in below_threshold:
                f_copy = dict(f)
                f_copy["triage_outcome"] = "below_threshold"
                triaged.append(cast(dict[str, JsonValue], f_copy))

        status: StageStatus = "ok"
        if not triaged:
            status = "partial"

        payload = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "triaged_findings": cast(
                list[JsonValue], cast(list[object], triaged)
            ),
            "summary": {
                "total_input": len(findings),
                "eligible": len(eligible),
                "debated": debated_count,
                "downgraded": downgraded_count,
                "maintained": debated_count - downgraded_count,
            },
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "triaged": len(triaged),
            "debated": debated_count,
            "downgraded": downgraded_count,
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
