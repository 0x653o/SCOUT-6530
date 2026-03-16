from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .schema import JsonValue

FEEDBACK_SCHEMA_VERSION = "terminator-feedback-v1"

_VALID_VERDICTS = frozenset({"confirmed", "false_positive", "wont_fix", "needs_info"})


@dataclass(frozen=True)
class TerminatorVerdict:
    """A single Terminator verdict on a previously reported finding."""

    finding_fingerprint: str  # SHA-256 based similarity key (fingerprinting.py compat)
    verdict: str  # "confirmed"|"false_positive"|"wont_fix"|"needs_info"
    confidence_override: float | None  # New confidence value (None = no change)
    rationale: str  # Verdict rationale
    original_run_id: str  # Original run ID
    timestamp: str  # ISO 8601


def _resolve_feedback_dir() -> Path:
    """Resolve feedback directory from env var or default."""
    env_val = os.environ.get("AIEDGE_FEEDBACK_DIR")
    if env_val is not None and env_val.strip():
        return Path(env_val).expanduser().resolve()
    return Path("aiedge-feedback")


def load_feedback_registry(feedback_dir: Path | None = None) -> list[TerminatorVerdict]:
    """Load Terminator verdict registry from disk.

    File format (``feedback_dir/registry.json``)::

        {
            "schema_version": "terminator-feedback-v1",
            "verdicts": [ ... ]
        }

    Validation rules:
    - ``schema_version`` must match ``FEEDBACK_SCHEMA_VERSION``.
    - Each verdict must contain the required fields.
    - ``verdict`` value must be one of the valid values.
    - Invalid individual entries are skipped (the whole file does NOT fail).

    Returns an empty list when the file is missing or the top-level
    structure is invalid.
    """
    if feedback_dir is None:
        feedback_dir = _resolve_feedback_dir()

    registry_path = feedback_dir / "registry.json"
    if not registry_path.is_file():
        return []

    try:
        raw = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    if not isinstance(raw, dict):
        return []

    if raw.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
        return []

    verdicts_any = raw.get("verdicts")
    if not isinstance(verdicts_any, list):
        return []

    result: list[TerminatorVerdict] = []
    for item_any in verdicts_any:
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, object], item_any)

        fp = item.get("finding_fingerprint")
        verdict_val = item.get("verdict")
        rationale = item.get("rationale")
        original_run_id = item.get("original_run_id")
        timestamp = item.get("timestamp")

        if not isinstance(fp, str) or not fp:
            continue
        if not isinstance(verdict_val, str) or verdict_val not in _VALID_VERDICTS:
            continue
        if not isinstance(rationale, str):
            rationale = ""
        if not isinstance(original_run_id, str):
            original_run_id = ""
        if not isinstance(timestamp, str):
            timestamp = ""

        conf_override: float | None = None
        conf_any = item.get("confidence_override")
        if isinstance(conf_any, (int, float)) and conf_any is not True and conf_any is not False:
            conf_override = float(max(0.0, min(1.0, float(conf_any))))

        result.append(
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict=verdict_val,
                confidence_override=conf_override,
                rationale=rationale,
                original_run_id=original_run_id,
                timestamp=timestamp,
            )
        )

    return result


def _fingerprint_prefix(fp: str, length: int = 16) -> str:
    """Return the first ``length`` characters of a fingerprint for prefix matching."""
    return fp[:length].lower()


def _find_matching_verdict(
    fingerprint: str,
    verdicts: list[TerminatorVerdict],
) -> TerminatorVerdict | None:
    """Find the most recent matching verdict by fingerprint prefix (first 16 chars)."""
    prefix = _fingerprint_prefix(fingerprint)
    best: TerminatorVerdict | None = None
    for v in verdicts:
        if _fingerprint_prefix(v.finding_fingerprint) == prefix:
            if best is None or v.timestamp > best.timestamp:
                best = v
    return best


def apply_scoring_calibration(
    candidates: list[dict[str, JsonValue]],
    verdicts: list[TerminatorVerdict],
    *,
    boost_factor: float = 1.15,
    suppress_factor: float = 0.5,
    max_score: float = 0.97,
) -> list[dict[str, JsonValue]]:
    """Calibrate candidate scores based on past Terminator verdicts.

    Rules:
    - ``confirmed`` -> similar finding score ``*= boost_factor`` (capped at *max_score*)
    - ``false_positive`` -> similar finding score ``*= suppress_factor``
    - ``wont_fix`` -> similar finding priority set to ``"low"``
    - ``needs_info`` -> no change

    Similarity matching uses the first 16 characters of the finding fingerprint
    (prefix match).

    If ``confidence_override`` is set on the verdict it is applied directly.

    Returns a **new** list (originals are not mutated).  Each calibrated
    candidate gains a ``"feedback_applied"`` annotation.
    """
    if not verdicts:
        return list(candidates)

    # Build prefix -> best verdict index for O(n) lookup.
    prefix_to_verdict: dict[str, TerminatorVerdict] = {}
    for v in verdicts:
        pfx = _fingerprint_prefix(v.finding_fingerprint)
        existing = prefix_to_verdict.get(pfx)
        if existing is None or v.timestamp > existing.timestamp:
            prefix_to_verdict[pfx] = v

    out: list[dict[str, JsonValue]] = []
    for candidate in candidates:
        c = dict(candidate)  # shallow copy

        # Try to match by candidate_id (which contains a sha256) or fingerprint fields
        candidate_id_any = c.get("candidate_id")
        fingerprint_any = c.get("fingerprint_sha256")

        matched_verdict: TerminatorVerdict | None = None

        for fp_source in (candidate_id_any, fingerprint_any):
            if not isinstance(fp_source, str) or not fp_source:
                continue
            # Strip "candidate:" prefix if present
            clean = fp_source
            if clean.startswith("candidate:"):
                clean = clean[len("candidate:"):]
            pfx = _fingerprint_prefix(clean)
            v = prefix_to_verdict.get(pfx)
            if v is not None:
                matched_verdict = v
                break

        if matched_verdict is None:
            out.append(c)
            continue

        score_any = c.get("score")
        score = float(score_any) if isinstance(score_any, (int, float)) else 0.0

        feedback_info: dict[str, JsonValue] = {
            "verdict": matched_verdict.verdict,
            "original_run_id": matched_verdict.original_run_id,
        }

        if matched_verdict.confidence_override is not None:
            score = matched_verdict.confidence_override
            c["score"] = round(min(max_score, score), 4)
            c["confidence"] = round(min(max_score, score), 4)
            feedback_info["override_applied"] = True
        elif matched_verdict.verdict == "confirmed":
            score = round(min(max_score, score * boost_factor), 4)
            c["score"] = score
            c["confidence"] = round(min(max_score, score), 4)
        elif matched_verdict.verdict == "false_positive":
            score = round(max(0.0, score * suppress_factor), 4)
            c["score"] = score
            c["confidence"] = round(max(0.0, score), 4)
        elif matched_verdict.verdict == "wont_fix":
            c["priority"] = "low"

        # needs_info -> no change

        c["feedback_applied"] = cast(JsonValue, feedback_info)
        out.append(c)

    return out


def generate_feedback_request(
    candidates: list[dict[str, JsonValue]],
    *,
    max_priority_findings: int = 10,
) -> dict[str, JsonValue]:
    """Generate a ``feedback_request`` section for ``firmware_handoff.json``.

    Selects findings most in need of review:
    - Confidence in the uncertain mid-range (0.4 -- 0.7)
    - Chain-backed candidates without prior feedback

    Returns a dict suitable for inclusion in the handoff payload.
    """
    scored: list[tuple[float, str]] = []
    for candidate in candidates:
        cid_any = candidate.get("candidate_id")
        if not isinstance(cid_any, str) or not cid_any:
            continue

        # Already has feedback -> skip
        if candidate.get("feedback_applied") is not None:
            continue

        conf_any = candidate.get("confidence")
        conf = float(conf_any) if isinstance(conf_any, (int, float)) else 0.5

        # Score by how close to the uncertain mid-range center (0.55)
        uncertainty = 1.0 - abs(conf - 0.55) / 0.55  # peaks at 0.55
        uncertainty = max(0.0, uncertainty)

        # Bonus for chain-backed candidates (more complex, more value in feedback)
        source_any = candidate.get("source")
        if isinstance(source_any, str) and source_any == "chain":
            uncertainty += 0.2

        scored.append((uncertainty, cid_any))

    scored.sort(key=lambda pair: (-pair[0], pair[1]))

    priority_ids: list[str] = [cid for _, cid in scored[:max_priority_findings]]

    return {
        "priority_findings": cast(list[JsonValue], cast(list[object], priority_ids)),
        "expected_feedback_path": "aiedge-feedback/registry.json",
        "feedback_schema_version": FEEDBACK_SCHEMA_VERSION,
    }
