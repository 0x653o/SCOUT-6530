# Repository Guidelines

## Project Structure & Module Organization
- `src/aiedge/`: core pipeline stages and CLI logic (`__main__.py`, `stage_registry.py`, `extraction.py`, `inventory.py`, `attack_surface.py`, etc.).
- `tests/`: pytest suite; primary pattern is `test_<feature>.py`.
- `scripts/`: verification and e2e helpers (`verify_*`, `e2e_*`, `release_gate.sh`).
- `docs/`: contracts, runbooks, and integration notes.
- Generated runtime artifacts (`aiedge-runs/`, `aiedge-inputs/`, `aiedge-8mb-runs/`) are local outputs; do not commit them.

## Build, Test, and Development Commands
- `./scout --help` — list CLI entry points.
- `./scout analyze <firmware.bin> --no-llm --stages tooling,extraction,structure,carving,firmware_profile,inventory` — run deterministic analysis (subset of stages).
- `./scout stages aiedge-runs/<run_id> --stages <comma-list>` — rerun selected stages on an existing run.
- `pytest -q` — run the full test suite.
- `pytest -q tests/test_cli_tui.py` — run a focused test module.
- `python3 scripts/verify_analyst_digest.py --run-dir aiedge-runs/<run_id>` and `python3 scripts/verify_verified_chain.py --run-dir aiedge-runs/<run_id>` — validate report and chain contracts.

## Coding Style & Naming Conventions
- Target Python 3.10+; use 4-space indentation and UTF-8.
- Keep type hints explicit (`Path`, `dict[str, object]`, `Protocol`) and function boundaries small.
- Use lowercase snake_case for modules and filenames (`firmware_profile.py`, `quality_policy.py`).
- Keep stage outputs deterministic and relative to `run_dir`; avoid absolute-path assumptions.

## Testing Guidelines
- Test framework is `pytest` (configured in `pyproject.toml` with `testpaths = ["tests"]` and `pythonpath = ["src"]`).
- Add/update tests for every behavior change, especially stage contracts, CLI flags, and verifier logic.
- Prefer behavior-driven names such as `test_<unit>_<expected_outcome>`.
- Use fixtures and `monkeypatch` to isolate filesystem, environment, and tool availability.

## Commit & Pull Request Guidelines
- Follow current history style: imperative subjects, with Conventional Commit prefixes when possible (`feat:`, `fix:`, `docs:`, `chore(...)`).
- Keep commits atomic and scoped to one concern.
- PRs should include: purpose, key changes, affected stages/files, exact test commands run, and output screenshots/snippets for TUI or viewer changes.
- Link related issue IDs or run IDs when relevant.
