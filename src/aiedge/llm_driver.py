"""Unified LLM CLI driver abstraction.

Consolidates the repeated codex-exec subprocess pattern from
llm_synthesis, exploit_autopoc, and llm_codex into a single module.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

ModelTier = Literal["haiku", "sonnet", "opus"]


@dataclass(frozen=True)
class LLMDriverResult:
    """Outcome of a single LLM CLI invocation (with retries)."""

    status: str  # "ok"|"skipped"|"timeout"|"error"|"nonzero_exit"|"missing_cli"
    stdout: str
    stderr: str
    argv: list[str]
    attempts: list[dict[str, object]]
    returncode: int


class LLMDriver(Protocol):
    """Structural protocol every LLM backend must satisfy."""

    @property
    def name(self) -> str: ...

    def available(self) -> bool: ...

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult: ...


class CodexCLIDriver:
    """Wraps ``codex exec --ephemeral`` with retry / fallback logic."""

    @property
    def name(self) -> str:
        return "codex"

    def available(self) -> bool:
        return shutil.which("codex") is not None

    def execute(
        self,
        *,
        prompt: str,
        run_dir: Path,
        timeout_s: float,
        max_attempts: int = 3,
        retryable_tokens: tuple[str, ...] = (),
        model_tier: ModelTier = "sonnet",
    ) -> LLMDriverResult:
        if not self.available():
            return LLMDriverResult(
                status="missing_cli",
                stdout="",
                stderr="codex executable not found",
                argv=[],
                attempts=[],
                returncode=-1,
            )

        base_argv = [
            "codex",
            "exec",
            "--ephemeral",
            "-s",
            "read-only",
            "-C",
            str(run_dir),
        ]
        argv = base_argv + [prompt]
        attempts: list[dict[str, object]] = []

        def _exec_once(cmd: list[str]) -> subprocess.CompletedProcess[str]:
            cp = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                stdin=subprocess.DEVNULL,
            )
            attempts.append(
                {
                    "argv": list(cmd),
                    "returncode": int(cp.returncode),
                    "stdout": cp.stdout or "",
                    "stderr": cp.stderr or "",
                }
            )
            return cp

        cp: subprocess.CompletedProcess[str] | None = None
        use_skip_git_repo_check = False

        for attempt_idx in range(max(1, max_attempts)):
            cmd = (
                base_argv + ["--skip-git-repo-check", prompt]
                if use_skip_git_repo_check
                else list(argv)
            )
            try:
                cp = _exec_once(cmd)
            except subprocess.TimeoutExpired as exc:
                attempts.append(
                    {
                        "argv": list(cmd),
                        "returncode": -1,
                        "stdout": (exc.stdout if isinstance(exc.stdout, str) else "") or "",
                        "stderr": (exc.stderr if isinstance(exc.stderr, str) else "") or "",
                        "exception": "TimeoutExpired",
                    }
                )
                if attempt_idx + 1 < max_attempts:
                    continue
                return LLMDriverResult(
                    status="timeout",
                    stdout=(exc.stdout if isinstance(exc.stdout, str) else "") or "",
                    stderr=(exc.stderr if isinstance(exc.stderr, str) else "") or "",
                    argv=list(cmd),
                    attempts=attempts,
                    returncode=-1,
                )
            except FileNotFoundError:
                return LLMDriverResult(
                    status="missing_cli",
                    stdout="",
                    stderr="codex executable not found",
                    argv=list(cmd),
                    attempts=attempts,
                    returncode=-1,
                )
            except Exception as exc:
                return LLMDriverResult(
                    status="error",
                    stdout="",
                    stderr=f"{type(exc).__name__}: {exc}",
                    argv=list(cmd),
                    attempts=attempts,
                    returncode=-1,
                )

            stderr_lc = (cp.stderr or "").lower()
            if cp.returncode == 0:
                break

            if "skip-git-repo-check" in stderr_lc and not use_skip_git_repo_check:
                use_skip_git_repo_check = True
                continue

            if retryable_tokens and any(
                token in stderr_lc for token in retryable_tokens
            ):
                continue

            break

        if cp is None:
            return LLMDriverResult(
                status="error",
                stdout="",
                stderr="codex execution did not produce a process result",
                argv=list(argv),
                attempts=attempts,
                returncode=-1,
            )

        status = "ok" if cp.returncode == 0 else "nonzero_exit"
        return LLMDriverResult(
            status=status,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            argv=list(attempts[-1]["argv"]) if attempts else list(argv),
            attempts=attempts,
            returncode=int(cp.returncode),
        )


def resolve_driver() -> LLMDriver:
    """Return the configured LLM driver (default: codex)."""
    driver_name = os.environ.get("AIEDGE_LLM_DRIVER", "codex").strip().lower()
    if driver_name == "codex":
        return CodexCLIDriver()
    return CodexCLIDriver()  # default fallback
