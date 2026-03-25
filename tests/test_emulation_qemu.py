# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aiedge.emulation_qemu import (
    detect_rootfs_arch,
    execute_binary,
    execute_service_probes,
    find_qemu_binary,
)


def _make_elf(path: Path, *, machine: int = 0x28, ei_data: int = 1) -> None:
    """Write a minimal 20-byte ELF header stub to *path*."""
    head = bytearray(20)
    head[0:4] = b"\x7fELF"
    head[4] = 1  # EI_CLASS = 32-bit
    head[5] = ei_data  # EI_DATA: 1=little, 2=big
    # e_machine at offset 18 (2 bytes)
    if ei_data == 1:
        head[18:20] = machine.to_bytes(2, "little")
    else:
        head[18:20] = machine.to_bytes(2, "big")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(head))


# ---------------------------------------------------------------------------
# detect_rootfs_arch
# ---------------------------------------------------------------------------


class TestDetectRootfsArch:
    def test_detects_arm_le(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)  # ei_data=1 (LE) by default
        assert detect_rootfs_arch(rootfs) == "arm_le"

    def test_detects_arm_be(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28, ei_data=2)
        assert detect_rootfs_arch(rootfs) == "arm_be"

    def test_detects_mips_be(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "usr" / "bin" / "httpd", machine=0x08, ei_data=2)
        assert detect_rootfs_arch(rootfs) == "mips_be"

    def test_detects_mips_le(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "usr" / "bin" / "httpd", machine=0x08, ei_data=1)
        assert detect_rootfs_arch(rootfs) == "mips_le"

    def test_detects_x86_64(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "sbin" / "init", machine=0x3E)
        assert detect_rootfs_arch(rootfs) == "x86_64"

    def test_detects_aarch64(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "usr" / "sbin" / "nginx", machine=0xB7)
        assert detect_rootfs_arch(rootfs) == "aarch64"

    def test_returns_none_when_no_elf(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        (rootfs / "bin").mkdir(parents=True)
        (rootfs / "bin" / "script.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        assert detect_rootfs_arch(rootfs) is None

    def test_returns_none_when_empty(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        assert detect_rootfs_arch(rootfs) is None

    def test_skips_non_file_entries(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        (rootfs / "bin" / "subdir").mkdir(parents=True)
        assert detect_rootfs_arch(rootfs) is None


# ---------------------------------------------------------------------------
# find_qemu_binary
# ---------------------------------------------------------------------------


class TestFindQemuBinary:
    def test_finds_arm_le(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-arm-static" else None,
        )
        assert find_qemu_binary("arm_le") == "/usr/bin/qemu-arm-static"

    def test_finds_arm_be(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-armeb-static" else None,
        )
        assert find_qemu_binary("arm_be") == "/usr/bin/qemu-armeb-static"

    def test_finds_generic_arm_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-armeb-static" else None,
        )
        assert find_qemu_binary("arm") == "/usr/bin/qemu-armeb-static"

    def test_returns_none_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("aiedge.emulation_qemu.shutil.which", lambda _: None)
        assert find_qemu_binary("arm_le") is None

    def test_returns_none_for_unknown_arch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("aiedge.emulation_qemu.shutil.which", lambda _: "/usr/bin/qemu")
        assert find_qemu_binary("sparc") is None


# ---------------------------------------------------------------------------
# execute_binary
# ---------------------------------------------------------------------------


class TestExecuteBinary:
    def test_successful_execution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="BusyBox v1.36.1\n", stderr=""
            )

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        result = execute_binary(
            "/usr/bin/qemu-arm-static",
            rootfs,
            "bin/busybox",
            ["--help"],
        )
        assert result.exit_code == 0
        assert result.binary == "bin/busybox"
        assert result.arch == "arm_le"
        assert "BusyBox" in result.stdout
        assert result.timed_out is False
        assert result.args == ["--help"]

    def test_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=args, timeout=5.0)

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        result = execute_binary(
            "/usr/bin/qemu-arm-static",
            rootfs,
            "bin/busybox",
            ["--help"],
            timeout_s=5.0,
        )
        assert result.timed_out is True
        assert result.exit_code == -1

    def test_oserror(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            raise OSError("No such file or directory")

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        result = execute_binary(
            "/usr/bin/qemu-arm-static",
            rootfs,
            "bin/busybox",
            ["--help"],
        )
        assert result.exit_code == -1
        assert result.timed_out is False
        assert "OSError" in result.stderr

    def test_nonzero_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="error\n"
            )

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        result = execute_binary(
            "/usr/bin/qemu-arm-static",
            rootfs,
            "bin/busybox",
            ["-V"],
        )
        assert result.exit_code == 1
        assert result.timed_out is False


# ---------------------------------------------------------------------------
# execute_service_probes
# ---------------------------------------------------------------------------


class TestExecuteServiceProbes:
    def test_probes_multiple_services(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)
        _make_elf(rootfs / "usr" / "sbin" / "httpd", machine=0x28)
        _make_elf(rootfs / "usr" / "sbin" / "dropbear", machine=0x28)

        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-arm-static" else None,
        )

        call_count = 0

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            nonlocal call_count
            call_count += 1
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout=f"output-{call_count}\n", stderr=""
            )

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        results = execute_service_probes(rootfs)
        assert len(results) >= 2
        binaries = {r.binary for r in results}
        assert "usr/sbin/httpd" in binaries
        assert "bin/busybox" in binaries

    def test_no_services_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "unknown_tool", machine=0x28)

        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-arm-static" else None,
        )

        results = execute_service_probes(rootfs)
        assert results == []

    def test_no_qemu_available(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)

        monkeypatch.setattr("aiedge.emulation_qemu.shutil.which", lambda _: None)

        results = execute_service_probes(rootfs)
        assert results == []

    def test_no_elf_in_rootfs(self, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        results = execute_service_probes(rootfs)
        assert results == []

    def test_max_probes_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        # Create all known service binaries
        _make_elf(rootfs / "usr" / "sbin" / "httpd", machine=0x28)
        _make_elf(rootfs / "usr" / "sbin" / "lighttpd", machine=0x28)
        _make_elf(rootfs / "usr" / "sbin" / "nginx", machine=0x28)
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)
        _make_elf(rootfs / "usr" / "sbin" / "dropbear", machine=0x28)
        _make_elf(rootfs / "usr" / "sbin" / "dnsmasq", machine=0x28)

        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-arm-static" else None,
        )

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="ok\n", stderr=""
            )

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        results = execute_service_probes(rootfs, max_probes=2)
        assert len(results) == 2

    def test_explicit_arch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "bin" / "busybox", machine=0x28)

        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-mipsel-static" else None,
        )

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="ok\n", stderr=""
            )

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        # Pass explicit arch to override ELF detection
        results = execute_service_probes(rootfs, arch="mipsel")
        assert len(results) >= 1

    def test_prefers_arg_set_with_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rootfs = tmp_path / "rootfs"
        _make_elf(rootfs / "usr" / "sbin" / "httpd", machine=0x28)

        monkeypatch.setattr(
            "aiedge.emulation_qemu.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "qemu-arm-static" else None,
        )

        call_args: list[list[str]] = []

        def fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            call_args.append(args)
            # First arg-set (--help) returns no output, second (-V) returns output
            if "--help" in args:
                return subprocess.CompletedProcess(
                    args=args, returncode=1, stdout="", stderr=""
                )
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="httpd v2.0\n", stderr=""
            )

        monkeypatch.setattr("aiedge.emulation_qemu.subprocess.run", fake_run)

        results = execute_service_probes(rootfs)
        assert len(results) == 1
        assert results[0].stdout == "httpd v2.0\n"
        assert results[0].args == ["-V"]
