from __future__ import annotations

"""False-positive verification stage.

Removes false positives from taint alerts using three known FP patterns
(sanitizer, non-propagating, system-file) via LLM few-shot classification.
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

_SCHEMA_VERSION = "fp-verification-v1"
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

_CONFIDENCE_REDUCTION = 0.3


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


def _build_fp_prompt(alert: dict[str, object]) -> str:
    alert_json = json.dumps(alert, indent=2, ensure_ascii=True)
    return (
        "You are a firmware vulnerability false-positive analyst.\n"
        "Determine if the following taint alert is a FALSE POSITIVE or a\n"
        "TRUE POSITIVE by checking against these three known FP patterns:\n\n"
        "## Known False Positive Patterns\n\n"
        "### 1. Sanitizer Pattern\n"
        "If the tainted value passes through a sanitizing function such as\n"
        "atoi(), strtol(), strtoul(), isValidIpAddr(), inet_aton(),\n"
        "inet_addr(), or any integer-conversion function, the taint is\n"
        "neutralized and cannot reach the sink as attacker-controlled\n"
        "string data. Mark as FP.\n\n"
        "### 2. Non-Propagating Pattern\n"
        "If the tainted value is ONLY used in a branch condition that\n"
        "selects between constant values (e.g., `if (param == 1) cmd =\n"
        '"/bin/true"; else cmd = "/bin/false";`), the attacker cannot\n'
        "control the sink argument. Mark as FP.\n\n"
        "### 3. System File Pattern\n"
        'If the source is fopen("/etc/..."), fopen("/proc/..."),\n'
        'fopen("/sys/..."), or reading from a fixed system file path that\n'
        "is not attacker-writable, the data is not externally controlled.\n"
        "Mark as FP.\n\n"
        "## Alert to Analyze\n"
        f"{alert_json}\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "verdict": "FP"|"TP",\n'
        '  "fp_pattern": "<pattern_name or null>",\n'
        '  "confidence_adjustment": -0.3 for FP or 0.0 for TP,\n'
        '  "rationale": "<brief explanation>"\n'
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


@dataclass(frozen=True)
class FPVerificationStage:
    """Remove false positives using 3 known FP patterns."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "fp_verification"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "fp_verification"
        out_json = stage_dir / "verified_alerts.json"

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
                "verified_alerts": [],
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

        # --- Load alerts from taint_propagation, findings, or attack_surface ---
        alerts: list[dict[str, object]] = []

        # Try taint_propagation alerts first
        taint_alerts_path = (
            run_dir / "stages" / "taint_propagation" / "alerts.json"
        )
        taint_data = _load_json_file(taint_alerts_path)
        if isinstance(taint_data, dict):
            alerts_any = cast(dict[str, object], taint_data).get("alerts")
            if isinstance(alerts_any, list):
                for a in cast(list[object], alerts_any):
                    if isinstance(a, dict):
                        alerts.append(cast(dict[str, object], a))

        # Fallback 1: try findings
        if not alerts:
            findings_path = (
                run_dir / "stages" / "findings" / "findings.json"
            )
            findings_data = _load_json_file(findings_path)
            if isinstance(findings_data, dict):
                f_any = cast(dict[str, object], findings_data).get("findings")
                if isinstance(f_any, list):
                    for f in cast(list[object], f_any):
                        if isinstance(f, dict):
                            alerts.append(cast(dict[str, object], f))

        # Fallback 2: attack_surface entries with confidence > 0.3
        if not alerts:
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
                        # Use confidence_calibrated (actual field name)
                        conf_any = (
                            entry.get("confidence")
                            or entry.get("confidence_calibrated")
                        )
                        if isinstance(conf_any, (int, float)) and float(conf_any) > 0.3:
                            # Normalize to alert format
                            alert_entry: dict[str, object] = {
                                "source_api": str(entry.get("surface", "")),
                                "source_binary": str(
                                    entry.get("observation", "")
                                ),
                                "sink_symbol": str(
                                    entry.get("classification", "candidate")
                                ),
                                "confidence": float(conf_any),
                                "path_description": str(
                                    entry.get("edge_semantics", "")
                                ),
                                "method": "attack_surface_fallback",
                                "evidence_refs": entry.get("evidence_refs", []),
                            }
                            alerts.append(alert_entry)
                    if alerts:
                        limitations.append(
                            "Using attack_surface entries as fallback "
                            "(taint_propagation and findings unavailable)"
                        )

        if not alerts:
            limitations.append(
                "No alerts from taint_propagation, findings, or attack_surface"
            )
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "status": "partial",
                "verified_alerts": [],
                "summary": {
                    "total_input": 0,
                    "false_positives": 0,
                    "true_positives": 0,
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
                details=cast(dict[str, JsonValue], {"verified": 0}),
                limitations=limitations,
            )

        # --- Filter alerts with confidence >= 0.3 ---
        eligible = [
            a for a in alerts
            if isinstance(a.get("confidence"), (int, float))
            and float(a["confidence"]) >= 0.3
        ]
        # Pass-through alerts below threshold unchanged
        below_threshold = [
            a for a in alerts
            if not isinstance(a.get("confidence"), (int, float))
            or float(a["confidence"]) < 0.3
        ]

        # --- LLM FP verification ---
        driver = resolve_driver()
        verified: list[dict[str, JsonValue]] = []
        fp_count = 0
        tp_count = 0

        if not driver.available():
            limitations.append("LLM driver not available for FP verification")
            # Pass all through unchanged
            for a in alerts:
                verified.append(cast(dict[str, JsonValue], dict(a)))
        else:
            for alert in eligible:
                prompt = _build_fp_prompt(alert)
                result = driver.execute(
                    prompt=prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                )

                alert_copy = dict(alert)
                if result.status == "ok":
                    parsed = _parse_json_response(result.stdout)
                    if parsed is not None:
                        verdict = str(parsed.get("verdict", "TP")).upper()
                        fp_pattern = parsed.get("fp_pattern")
                        rationale = str(parsed.get("rationale", ""))

                        if verdict == "FP":
                            orig_conf = float(alert.get("confidence", 0.5))
                            new_conf = _clamp01(
                                orig_conf - _CONFIDENCE_REDUCTION
                            )
                            alert_copy["confidence"] = new_conf
                            alert_copy["original_confidence"] = orig_conf
                            alert_copy["fp_verdict"] = "FP"
                            alert_copy["fp_pattern"] = fp_pattern
                            alert_copy["fp_rationale"] = rationale
                            fp_count += 1
                        else:
                            alert_copy["fp_verdict"] = "TP"
                            alert_copy["fp_rationale"] = rationale
                            tp_count += 1
                    else:
                        alert_copy["fp_verdict"] = "unverified"
                        alert_copy["fp_rationale"] = "LLM response parse failure"
                        limitations.append(
                            "One or more FP verification responses could not be parsed"
                        )
                else:
                    alert_copy["fp_verdict"] = "unverified"
                    alert_copy["fp_rationale"] = f"LLM call failed: {result.status}"

                verified.append(cast(dict[str, JsonValue], alert_copy))

            # Add below-threshold alerts unchanged
            for a in below_threshold:
                a_copy = dict(a)
                a_copy["fp_verdict"] = "below_threshold"
                verified.append(cast(dict[str, JsonValue], a_copy))

        status: StageStatus = "ok"
        if not verified:
            status = "partial"

        payload = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "verified_alerts": cast(
                list[JsonValue], cast(list[object], verified)
            ),
            "summary": {
                "total_input": len(alerts),
                "eligible_checked": len(eligible),
                "false_positives": fp_count,
                "true_positives": tp_count,
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
            "verified": len(verified),
            "false_positives": fp_count,
            "true_positives": tp_count,
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
