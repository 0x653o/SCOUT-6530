#!/usr/bin/env python3
"""Analyze benchmark findings for TP/FP classification.

Reads benchmark_summary.csv and archived findings to produce:
- Finding type distribution
- TP candidates (known CVE match + taint path)
- FP candidates (generic signals without taint path)
- 0-day candidates (taint path + no known CVE + recent firmware)

Usage:
    python3 scripts/analyze_findings.py --results-dir benchmark-results/firmae-YYYYMMDD_HHMM
    python3 scripts/analyze_findings.py --results-dir benchmark-results/firmae-YYYYMMDD_HHMM --output analysis_report.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Finding ID → type mapping
# ---------------------------------------------------------------------------
# Finding IDs follow the pattern: aiedge.findings.<category>.<name>
# We map them to the short keys used in the spec.

_FINDING_TYPE_MAP: dict[str, str] = {
    "aiedge.findings.web.exec_sink_overlap": "web_exec_sink_overlap",
    "aiedge.findings.inventory.string_hits_present": "string_hits_present",
    "aiedge.findings.exploit.candidate_plan": "exploit_candidate_plan",
    "aiedge.findings.credential.private_key_material": "private_key_material",
    "aiedge.findings.credential.hardcoded_credential": "private_key_material",
    # secrets
    "aiedge.findings.secrets.private_key_pem": "private_key_material",
    # debug / backdoor
    "aiedge.findings.debug.telnet_enablement": "telnet_enablement",
    # no-signal sentinel (stage ran but found nothing)
    "aiedge.findings.no_signals": "no_signals",
}


def _classify_finding_id(finding_id: str) -> str:
    """Return the canonical short type key for a finding id."""
    if finding_id in _FINDING_TYPE_MAP:
        return _FINDING_TYPE_MAP[finding_id]
    # Fallback: derive from last two components
    parts = finding_id.rsplit(".", 2)
    return parts[-1] if parts else finding_id


# ---------------------------------------------------------------------------
# Archive resolution helpers  (shared logic with cve_rematch.py)
# ---------------------------------------------------------------------------

def _find_run_dir(archive_sha_dir: Path) -> Path | None:
    """Walk the archive tree to find the aiedge-runs/<run_id> directory."""
    for p in archive_sha_dir.rglob("stages"):
        if p.is_dir():
            return p.parent
    return None


# ---------------------------------------------------------------------------
# Per-firmware data loading
# ---------------------------------------------------------------------------

def _load_findings(run_dir: Path) -> list[dict]:
    """Load findings from stages/findings/findings.json."""
    path = run_dir / "stages" / "findings" / "findings.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        findings = data.get("findings", [])
        return findings if isinstance(findings, list) else []
    return []


def _has_web_taint(run_dir: Path) -> bool:
    """Return True if taint_results.json has at least one web_server=True entry."""
    path = run_dir / "stages" / "taint_propagation" / "taint_results.json"
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return False
    results = data.get("results", [])
    return any(r.get("web_server") is True for r in results if isinstance(r, dict))


def _has_any_taint(run_dir: Path) -> bool:
    """Return True if taint_results.json has at least one taint_reaches_sink=True entry."""
    path = run_dir / "stages" / "taint_propagation" / "taint_results.json"
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return False
    results = data.get("results", [])
    return any(r.get("taint_reaches_sink") is True for r in results if isinstance(r, dict))


def _load_taint_results(run_dir: Path) -> list[dict]:
    """Return raw taint result entries."""
    path = run_dir / "stages" / "taint_propagation" / "taint_results.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    results = data.get("results", [])
    return results if isinstance(results, list) else []


def _has_cve_match(run_dir: Path) -> bool:
    """Return True if the cve_scan stage produced any matches.

    cve_scan/stage.json artifacts list may contain a cve_matches.json path.
    Fall back to checking the artifacts list for non-empty results.
    """
    stage_json = run_dir / "stages" / "cve_scan" / "stage.json"
    if not stage_json.exists():
        return False
    try:
        data = json.loads(stage_json.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return False
    artifacts = data.get("artifacts", [])
    # artifacts is a list of {"path": ..., "sha256": ...} dicts
    for art in artifacts:
        art_path_str = art.get("path", "") if isinstance(art, dict) else str(art)
        art_path = run_dir / art_path_str
        if art_path.exists() and "cve" in art_path.name.lower():
            try:
                matches = json.loads(art_path.read_text(encoding="utf-8", errors="replace"))
                if matches:
                    return True
            except (json.JSONDecodeError, OSError):
                pass
    # Also check direct file
    direct = run_dir / "stages" / "cve_scan" / "cve_matches.json"
    if direct.exists():
        try:
            matches = json.loads(direct.read_text(encoding="utf-8", errors="replace"))
            return bool(matches)
        except (json.JSONDecodeError, OSError):
            pass
    return False


def _extract_hardening(run_dir: Path) -> dict[str, bool] | None:
    """Return worst-case (most permissive) hardening flags across binaries."""
    path = run_dir / "stages" / "inventory" / "binary_analysis.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    hits = data.get("hits", [])
    if not hits:
        return None
    # Aggregate: flag is False (weak) if ANY binary lacks it
    any_no_pie = any(not h.get("hardening", {}).get("pie", True) for h in hits)
    any_no_canary = any(not h.get("hardening", {}).get("canary", True) for h in hits)
    any_no_nx = any(not h.get("hardening", {}).get("nx", True) for h in hits)
    return {"pie": not any_no_pie, "canary": not any_no_canary, "nx": not any_no_nx}


# ---------------------------------------------------------------------------
# TP/FP classification
# ---------------------------------------------------------------------------

def _classify_tp_fp(
    findings: list[dict],
    has_web_taint: bool,
    has_any_taint_: bool,
    has_cve: bool,
) -> str:
    """Return one of: strong_tp, likely_tp, zero_day, weak."""
    has_affected_binaries = any(
        bool(f.get("affected_binaries")) for f in findings
    )

    # Strong TP: CVE match + taint path + affected binaries named
    if has_cve and has_any_taint_ and has_affected_binaries:
        return "strong_tp"

    # Likely TP: web-server taint path (no CVE required)
    if has_web_taint:
        return "likely_tp"

    # 0-day candidate: taint present but no CVE match
    if has_any_taint_ and not has_cve:
        return "zero_day"

    return "weak"


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

def process_results_dir(
    results_dir: Path,
    output_path: Path | None,
    verbose: bool,
) -> int:
    summary_csv = results_dir / "benchmark_summary.csv"
    if not summary_csv.exists():
        print(f"ERROR: {summary_csv} not found", file=sys.stderr)
        return 1

    archives_root = results_dir / "archives"
    if not archives_root.exists():
        print(f"ERROR: {archives_root} not found", file=sys.stderr)
        return 1

    total_firmware = 0
    total_findings = 0
    finding_types: dict[str, int] = defaultdict(int)
    tp_counts = {"strong_tp": 0, "likely_tp": 0, "weak": 0, "zero_day_candidates": 0}
    vendor_breakdown: dict[str, dict[str, int]] = defaultdict(lambda: {"findings": 0, "cve_matches": 0})
    zero_day_list: list[dict] = []
    skipped = 0

    with summary_csv.open(encoding="utf-8", newline="") as fh:
        entries = list(csv.DictReader(fh))

    for entry in entries:
        total_firmware += 1
        vendor = entry.get("vendor", "").strip().lower()
        firmware_filename = entry.get("firmware", "").strip()
        sha = entry.get("sha256", "").strip()

        if not sha or not vendor:
            skipped += 1
            continue

        archive_sha_dir = archives_root / vendor / sha
        if not archive_sha_dir.is_dir():
            if verbose:
                print(f"  SKIP (no archive): {vendor}/{sha}")
            skipped += 1
            continue

        run_dir = _find_run_dir(archive_sha_dir)
        if run_dir is None:
            if verbose:
                print(f"  SKIP (no run_dir): {vendor}/{sha}")
            skipped += 1
            continue

        findings = _load_findings(run_dir)
        has_web_taint = _has_web_taint(run_dir)
        has_any_taint_ = _has_any_taint(run_dir)
        has_cve = _has_cve_match(run_dir)
        hardening = _extract_hardening(run_dir)

        # Accumulate finding types
        for f in findings:
            fid = f.get("id", "")
            ftype = _classify_finding_id(fid)
            finding_types[ftype] += 1
            total_findings += 1

        vendor_breakdown[vendor]["findings"] += len(findings)
        if has_cve:
            vendor_breakdown[vendor]["cve_matches"] += 1

        classification = _classify_tp_fp(findings, has_web_taint, has_any_taint_, has_cve)

        if classification == "strong_tp":
            tp_counts["strong_tp"] += 1
        elif classification == "likely_tp":
            tp_counts["likely_tp"] += 1
        elif classification == "zero_day":
            tp_counts["zero_day_candidates"] += 1
            # Build zero-day candidate record
            taint_results = _load_taint_results(run_dir)
            web_taint_entries = [r for r in taint_results if r.get("web_server") is True]
            representative = web_taint_entries[0] if web_taint_entries else (taint_results[0] if taint_results else {})
            binary_path = representative.get("source_binary", "")
            binary_name = Path(binary_path).name if binary_path else ""
            zero_day_list.append({
                "firmware": firmware_filename,
                "vendor": vendor,
                "binary": binary_name,
                "finding": next(
                    (_classify_finding_id(f.get("id", "")) for f in findings),
                    "unknown",
                ),
                "taint_path": True,
                "hardening": {
                    "pie": hardening.get("pie", None) if hardening else None,
                    "canary": hardening.get("canary", None) if hardening else None,
                },
                "reason": "taint path + no CVE match + no hardening"
                if hardening and not hardening.get("pie") and not hardening.get("canary")
                else "taint path + no CVE match",
            })
        else:
            tp_counts["weak"] += 1

    # --- Precision estimate ---
    strong = tp_counts["strong_tp"]
    weak = tp_counts["weak"]
    denom_optimistic = strong + tp_counts["likely_tp"] + tp_counts["zero_day_candidates"] + weak
    denom_conservative = strong + weak
    precision = {
        "optimistic": round((strong + tp_counts["likely_tp"]) / denom_optimistic, 3)
        if denom_optimistic > 0 else 0.0,
        "conservative": round(strong / denom_conservative, 3) if denom_conservative > 0 else 0.0,
        "method": "optimistic = (strong_tp + likely_tp) / total; conservative = strong_tp / (strong_tp + weak)",
    }

    report = {
        "total_firmware": total_firmware,
        "skipped": skipped,
        "total_findings": total_findings,
        "finding_types": dict(finding_types),
        "tp_candidates": {
            "strong_tp": tp_counts["strong_tp"],
            "likely_tp": tp_counts["likely_tp"],
            "weak": tp_counts["weak"],
            "zero_day_candidates": tp_counts["zero_day_candidates"],
        },
        "precision_estimate": precision,
        "vendor_breakdown": {v: dict(d) for v, d in vendor_breakdown.items()},
        "zero_day_candidates": zero_day_list,
    }

    # --- Output ---
    report_json = json.dumps(report, indent=2, ensure_ascii=False)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_json, encoding="utf-8")
        print(f"Wrote report → {output_path}")
    else:
        print(report_json)

    # --- Console summary (always to stderr when writing to file) ---
    out = sys.stderr if output_path else sys.stdout
    print(file=out)
    print("=" * 60, file=out)
    print(f"Total firmware:          {total_firmware}", file=out)
    print(f"Skipped (no archive):    {skipped}", file=out)
    print(f"Total findings:          {total_findings}", file=out)
    print(file=out)
    print("Finding type distribution:", file=out)
    for ftype, cnt in sorted(finding_types.items(), key=lambda x: -x[1]):
        print(f"  {ftype:<40} {cnt}", file=out)
    print(file=out)
    print("TP/FP classification:", file=out)
    print(f"  Strong TP:             {tp_counts['strong_tp']}", file=out)
    print(f"  Likely TP:             {tp_counts['likely_tp']}", file=out)
    print(f"  Weak / FP:             {tp_counts['weak']}", file=out)
    print(f"  0-day candidates:      {tp_counts['zero_day_candidates']}", file=out)
    print(file=out)
    print(f"Precision estimate (optimistic):    {precision['optimistic']:.1%}", file=out)
    print(f"Precision estimate (conservative):  {precision['conservative']:.1%}", file=out)
    print(file=out)
    print("Vendor breakdown:", file=out)
    for v, d in sorted(vendor_breakdown.items()):
        print(f"  {v:<20} findings={d['findings']} cve_matches={d['cve_matches']}", file=out)

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Analyze benchmark findings for TP/FP classification.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--results-dir",
        required=True,
        type=Path,
        metavar="DIR",
        help="Benchmark results directory (contains benchmark_summary.csv and archives/).",
    )
    p.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write JSON report to FILE instead of stdout.",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-firmware skip reasons.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return process_results_dir(
        results_dir=args.results_dir.resolve(),
        output_path=args.output.resolve() if args.output else None,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    sys.exit(main())
