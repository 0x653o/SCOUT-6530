"""Tests for the Terminator feedback loop module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from aiedge.terminator_feedback import (
    FEEDBACK_SCHEMA_VERSION,
    TerminatorVerdict,
    apply_scoring_calibration,
    generate_feedback_request,
    load_feedback_registry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_registry(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _make_candidate(
    candidate_id: str = "candidate:abcdef1234567890",
    score: float = 0.6,
    confidence: float = 0.6,
    priority: str = "medium",
    source: str = "chain",
    **extra: object,
) -> dict:
    c: dict = {
        "candidate_id": candidate_id,
        "score": score,
        "confidence": confidence,
        "priority": priority,
        "source": source,
    }
    c.update(extra)
    return c


def _make_verdict(
    finding_fingerprint: str = "abcdef1234567890" + "0" * 48,
    verdict: str = "confirmed",
    confidence_override: float | None = None,
    rationale: str = "test rationale",
    original_run_id: str = "run-001",
    timestamp: str = "2026-03-16T00:00:00Z",
) -> dict:
    d: dict = {
        "finding_fingerprint": finding_fingerprint,
        "verdict": verdict,
        "rationale": rationale,
        "original_run_id": original_run_id,
        "timestamp": timestamp,
    }
    if confidence_override is not None:
        d["confidence_override"] = confidence_override
    return d


# ---------------------------------------------------------------------------
# load_feedback_registry
# ---------------------------------------------------------------------------

class TestLoadFeedbackRegistry:
    def test_file_not_found_returns_empty(self, tmp_path: Path) -> None:
        result = load_feedback_registry(tmp_path / "nonexistent")
        assert result == []

    def test_valid_registry(self, tmp_path: Path) -> None:
        registry = {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [
                _make_verdict(verdict="confirmed"),
                _make_verdict(
                    finding_fingerprint="bbbbbbbbbbbbbbbb" + "1" * 48,
                    verdict="false_positive",
                    confidence_override=0.15,
                ),
            ],
        }
        _write_registry(tmp_path / "registry.json", registry)
        result = load_feedback_registry(tmp_path)
        assert len(result) == 2
        assert result[0].verdict == "confirmed"
        assert result[0].confidence_override is None
        assert result[1].verdict == "false_positive"
        assert result[1].confidence_override == 0.15

    def test_empty_verdicts_list(self, tmp_path: Path) -> None:
        registry = {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [],
        }
        _write_registry(tmp_path / "registry.json", registry)
        result = load_feedback_registry(tmp_path)
        assert result == []

    def test_wrong_schema_version(self, tmp_path: Path) -> None:
        registry = {
            "schema_version": "wrong-version",
            "verdicts": [_make_verdict()],
        }
        _write_registry(tmp_path / "registry.json", registry)
        result = load_feedback_registry(tmp_path)
        assert result == []

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.json"
        path.write_text("not json", encoding="utf-8")
        result = load_feedback_registry(tmp_path)
        assert result == []

    def test_non_dict_root(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        result = load_feedback_registry(tmp_path)
        assert result == []

    def test_invalid_entries_skipped(self, tmp_path: Path) -> None:
        registry = {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [
                _make_verdict(verdict="confirmed"),  # valid
                {"finding_fingerprint": "", "verdict": "confirmed"},  # empty fp
                {"finding_fingerprint": "abc", "verdict": "invalid_val"},  # bad verdict
                "not a dict",  # not a dict
                {"verdict": "confirmed"},  # missing fp
                _make_verdict(verdict="wont_fix"),  # valid
            ],
        }
        _write_registry(tmp_path / "registry.json", registry)
        result = load_feedback_registry(tmp_path)
        assert len(result) == 2
        assert result[0].verdict == "confirmed"
        assert result[1].verdict == "wont_fix"

    def test_confidence_override_clamped(self, tmp_path: Path) -> None:
        registry = {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [
                _make_verdict(confidence_override=1.5),
                _make_verdict(
                    finding_fingerprint="cc" * 32,
                    confidence_override=-0.3,
                ),
            ],
        }
        _write_registry(tmp_path / "registry.json", registry)
        result = load_feedback_registry(tmp_path)
        assert result[0].confidence_override == 1.0
        assert result[1].confidence_override == 0.0

    def test_env_var_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        registry = {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "verdicts": [_make_verdict()],
        }
        _write_registry(tmp_path / "registry.json", registry)
        monkeypatch.setenv("AIEDGE_FEEDBACK_DIR", str(tmp_path))
        # Call without explicit dir to test env resolution
        result = load_feedback_registry(None)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# apply_scoring_calibration
# ---------------------------------------------------------------------------

class TestApplyScoringCalibration:
    def test_no_verdicts_returns_copy(self) -> None:
        candidates = [_make_candidate()]
        result = apply_scoring_calibration(candidates, [])
        assert len(result) == 1
        assert result[0]["score"] == 0.6
        # Must be a different list
        assert result is not candidates

    def test_confirmed_boost(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [_make_candidate(candidate_id=f"candidate:{fp}", score=0.6)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="confirmed",
                confidence_override=None,
                rationale="real finding",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        assert result[0]["score"] == round(min(0.97, 0.6 * 1.15), 4)
        assert "feedback_applied" in result[0]

    def test_false_positive_suppress(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [_make_candidate(candidate_id=f"candidate:{fp}", score=0.8)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="false_positive",
                confidence_override=None,
                rationale="fp",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        assert result[0]["score"] == round(0.8 * 0.5, 4)

    def test_wont_fix_sets_low_priority(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [
            _make_candidate(
                candidate_id=f"candidate:{fp}", score=0.7, priority="high"
            )
        ]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="wont_fix",
                confidence_override=None,
                rationale="accepted risk",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        assert result[0]["priority"] == "low"

    def test_needs_info_no_change(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [_make_candidate(candidate_id=f"candidate:{fp}", score=0.6)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="needs_info",
                confidence_override=None,
                rationale="more info needed",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        # Score unchanged, but feedback_applied is set
        assert result[0]["score"] == 0.6
        assert "feedback_applied" in result[0]

    def test_no_match_no_change(self) -> None:
        candidates = [_make_candidate(candidate_id="candidate:aaaa" + "0" * 60)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint="bbbb" + "1" * 60,
                verdict="confirmed",
                confidence_override=None,
                rationale="r",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        assert result[0]["score"] == 0.6
        assert "feedback_applied" not in result[0]

    def test_confidence_override_applied_directly(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [_make_candidate(candidate_id=f"candidate:{fp}", score=0.8)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="confirmed",
                confidence_override=0.35,
                rationale="override",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        assert result[0]["score"] == 0.35
        assert result[0]["confidence"] == 0.35
        fb = result[0]["feedback_applied"]
        assert isinstance(fb, dict)
        assert fb.get("override_applied") is True

    def test_boost_capped_at_max(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [_make_candidate(candidate_id=f"candidate:{fp}", score=0.95)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="confirmed",
                confidence_override=None,
                rationale="r",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        result = apply_scoring_calibration(candidates, verdicts)
        assert result[0]["score"] <= 0.97

    def test_originals_not_mutated(self) -> None:
        fp = "abcdef1234567890" + "0" * 48
        candidates = [_make_candidate(candidate_id=f"candidate:{fp}", score=0.6)]
        verdicts = [
            TerminatorVerdict(
                finding_fingerprint=fp,
                verdict="confirmed",
                confidence_override=None,
                rationale="r",
                original_run_id="run-001",
                timestamp="2026-03-16T00:00:00Z",
            )
        ]
        _ = apply_scoring_calibration(candidates, verdicts)
        assert candidates[0]["score"] == 0.6
        assert "feedback_applied" not in candidates[0]


# ---------------------------------------------------------------------------
# generate_feedback_request
# ---------------------------------------------------------------------------

class TestGenerateFeedbackRequest:
    def test_empty_candidates(self) -> None:
        result = generate_feedback_request([])
        assert result["priority_findings"] == []
        assert result["feedback_schema_version"] == FEEDBACK_SCHEMA_VERSION

    def test_selects_uncertain_candidates(self) -> None:
        candidates = [
            _make_candidate(candidate_id="c1", confidence=0.55, source="chain"),
            _make_candidate(candidate_id="c2", confidence=0.1, source="pattern"),
            _make_candidate(candidate_id="c3", confidence=0.95, source="pattern"),
            _make_candidate(candidate_id="c4", confidence=0.5, source="chain"),
        ]
        result = generate_feedback_request(candidates, max_priority_findings=2)
        ids = result["priority_findings"]
        assert isinstance(ids, list)
        assert len(ids) == 2
        # c1 and c4 have mid-range confidence + chain bonus -> prioritized
        assert "c1" in ids
        assert "c4" in ids

    def test_skips_already_feedbacked(self) -> None:
        candidates = [
            _make_candidate(
                candidate_id="c1",
                confidence=0.55,
                feedback_applied={"verdict": "confirmed"},
            ),
            _make_candidate(candidate_id="c2", confidence=0.55),
        ]
        result = generate_feedback_request(candidates)
        ids = result["priority_findings"]
        assert "c1" not in ids
        assert "c2" in ids

    def test_max_priority_findings_limit(self) -> None:
        candidates = [
            _make_candidate(candidate_id=f"c{i}", confidence=0.55)
            for i in range(20)
        ]
        result = generate_feedback_request(candidates, max_priority_findings=5)
        assert len(result["priority_findings"]) == 5

    def test_result_structure(self) -> None:
        result = generate_feedback_request([_make_candidate()])
        assert "priority_findings" in result
        assert "expected_feedback_path" in result
        assert "feedback_schema_version" in result
        assert result["expected_feedback_path"] == "aiedge-feedback/registry.json"


# ---------------------------------------------------------------------------
# TerminatorVerdict data integrity
# ---------------------------------------------------------------------------

class TestTerminatorVerdict:
    def test_frozen(self) -> None:
        tv = TerminatorVerdict(
            finding_fingerprint="abc",
            verdict="confirmed",
            confidence_override=None,
            rationale="r",
            original_run_id="run-001",
            timestamp="2026-03-16T00:00:00Z",
        )
        with pytest.raises(AttributeError):
            tv.verdict = "false_positive"  # type: ignore[misc]

    def test_fields(self) -> None:
        tv = TerminatorVerdict(
            finding_fingerprint="fp123",
            verdict="false_positive",
            confidence_override=0.42,
            rationale="test",
            original_run_id="run-002",
            timestamp="2026-03-16T12:00:00Z",
        )
        assert tv.finding_fingerprint == "fp123"
        assert tv.verdict == "false_positive"
        assert tv.confidence_override == 0.42
        assert tv.rationale == "test"
        assert tv.original_run_id == "run-002"
        assert tv.timestamp == "2026-03-16T12:00:00Z"
