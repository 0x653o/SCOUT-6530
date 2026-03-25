from __future__ import annotations

from aiedge.poc_templates import (
    _REGISTRY,
    PoCContext,
    list_templates,
    select_template,
)

# Tokens that must not appear in generated PoC source code.
# These are the same tokens checked by exploit_autopoc._DISALLOWED_PLUGIN_TOKENS.
_DISALLOWED_TOKENS: tuple[str, ...] = (
    "subprocess.",
    "pty.",
    "pexpect",
    "paramiko",
    "telnetlib",
    "multiprocessing",
    "threading.",
    "fork" + "(",
    "exe" + "c(",
)


def _make_ctx(
    *,
    families: list[str] | None = None,
    chain_id: str = "test_chain",
) -> PoCContext:
    return PoCContext(
        chain_id=chain_id,
        target_service="http",
        candidate_id="candidate:test",
        candidate_summary="Test candidate",
        evidence_refs=["stages/findings/test.json"],
        families=families or [],
    )


# ------------------------------------------------------------------
# Template registry sanity checks
# ------------------------------------------------------------------


def test_list_templates_returns_sorted_names() -> None:
    names = list_templates()
    assert names == sorted(names)
    assert len(names) >= 4
    assert "cmd_injection" in names
    assert "path_traversal" in names
    assert "auth_bypass" in names
    assert "info_disclosure" in names


def test_select_template_returns_none_for_empty_families() -> None:
    assert select_template([]) is None


def test_select_template_returns_none_for_unknown_families() -> None:
    assert select_template(["completely_unknown_family_xyz"]) is None


def test_select_template_matches_cmd_injection() -> None:
    template = select_template(["cmd_injection"])
    assert template is not None
    assert template.vuln_type == "cmd_injection"


def test_select_template_matches_cmd_exec_injection_risk() -> None:
    template = select_template(["cmd_exec_injection_risk"])
    assert template is not None
    assert template.vuln_type == "cmd_injection"


def test_select_template_matches_path_traversal() -> None:
    template = select_template(["path_traversal"])
    assert template is not None
    assert template.vuln_type == "path_traversal"


def test_select_template_matches_lfi() -> None:
    template = select_template(["lfi"])
    assert template is not None
    assert template.vuln_type == "path_traversal"


def test_select_template_matches_auth_bypass() -> None:
    template = select_template(["auth_bypass"])
    assert template is not None
    assert template.vuln_type == "auth_bypass"


def test_select_template_matches_default_credentials() -> None:
    template = select_template(["default_credentials"])
    assert template is not None
    assert template.vuln_type == "auth_bypass"


def test_select_template_matches_info_disclosure() -> None:
    template = select_template(["info_disclosure"])
    assert template is not None
    assert template.vuln_type == "info_disclosure"


def test_select_template_matches_debug_endpoint() -> None:
    template = select_template(["debug_endpoint"])
    assert template is not None
    assert template.vuln_type == "info_disclosure"


def test_select_template_picks_best_match_with_multiple_families() -> None:
    # cmd_injection has both of these in its families
    template = select_template(["cmd_exec_injection_risk", "authenticated_mgmt_cmd_path"])
    assert template is not None
    assert template.vuln_type == "cmd_injection"


# ------------------------------------------------------------------
# Generated source quality checks for each template
# ------------------------------------------------------------------


def _assert_valid_plugin_source(source: str) -> None:
    """Common assertions for all generated plugin sources."""
    # Must compile
    compile(source, "<test_generated>", "exec")

    # Must contain PoC and PoCResult classes
    assert "class PoC" in source
    assert "class PoCResult" in source

    # Must contain required methods
    assert "def setup(" in source
    assert "def execute(" in source
    assert "def cleanup(" in source

    # Must contain readback_hash
    assert "readback_hash" in source

    # Must not contain disallowed tokens
    for token in _DISALLOWED_TOKENS:
        assert token not in source, f"Disallowed token found: {token}"


def test_cmd_injection_template_generates_valid_source() -> None:
    template = select_template(["cmd_injection"])
    assert template is not None
    ctx = _make_ctx(families=["cmd_injection"])
    source = template.generate(ctx)
    _assert_valid_plugin_source(source)
    assert "probe=cmd_injection" in source
    assert "uid=" in source


def test_path_traversal_template_generates_valid_source() -> None:
    template = select_template(["path_traversal"])
    assert template is not None
    ctx = _make_ctx(families=["path_traversal"])
    source = template.generate(ctx)
    _assert_valid_plugin_source(source)
    assert "probe=path_traversal" in source
    assert "root:" in source


def test_auth_bypass_template_generates_valid_source() -> None:
    template = select_template(["auth_bypass"])
    assert template is not None
    ctx = _make_ctx(families=["auth_bypass"])
    source = template.generate(ctx)
    _assert_valid_plugin_source(source)
    assert "probe=auth_bypass" in source


def test_info_disclosure_template_generates_valid_source() -> None:
    template = select_template(["info_disclosure"])
    assert template is not None
    ctx = _make_ctx(families=["info_disclosure"])
    source = template.generate(ctx)
    _assert_valid_plugin_source(source)
    assert "probe=info_disclosure" in source


def test_generated_sources_embed_chain_id() -> None:
    for vuln_type in list_templates():
        template = _REGISTRY[vuln_type]
        ctx = _make_ctx(
            families=list(template.families)[:1],
            chain_id="test_chain_xyz",
        )
        source = template.generate(ctx)
        assert "test_chain_xyz" in source, f"{vuln_type} did not embed chain_id"


def test_generated_sources_embed_candidate_id() -> None:
    for vuln_type in list_templates():
        template = _REGISTRY[vuln_type]
        ctx = PoCContext(
            chain_id="chain_test",
            target_service="http",
            candidate_id="candidate:embedded_test",
            candidate_summary="Summary test",
            evidence_refs=[],
            families=list(template.families)[:1],
        )
        source = template.generate(ctx)
        assert "candidate:embedded_test" in source, (
            f"{vuln_type} did not embed candidate_id"
        )


# ------------------------------------------------------------------
# Integration with exploit_autopoc._plugin_source
# ------------------------------------------------------------------


def test_plugin_source_uses_template_for_cmd_injection_families() -> None:
    from aiedge.exploit_autopoc import _plugin_source

    source = _plugin_source(
        chain_id="test_chain",
        target_service="http",
        candidate_id="candidate:test",
        candidate_summary="test summary",
        fallback_read_rel="",
        families=["cmd_exec_injection_risk"],
    )
    # Should use cmd_injection template, not TCP banner
    assert "probe=cmd_injection" in source
    _assert_valid_plugin_source(source)


def test_plugin_source_falls_back_to_tcp_banner_for_unknown_families() -> None:
    from aiedge.exploit_autopoc import _plugin_source

    source = _plugin_source(
        chain_id="test_chain",
        target_service="http",
        candidate_id="candidate:test",
        candidate_summary="test summary",
        fallback_read_rel="",
        families=["completely_unknown_family_xyz"],
    )
    # Should fall back to TCP banner
    assert "probe=tcp_banner" in source


def test_plugin_source_falls_back_to_tcp_banner_when_no_families() -> None:
    from aiedge.exploit_autopoc import _plugin_source

    source = _plugin_source(
        chain_id="test_chain",
        target_service="http",
        candidate_id="candidate:test",
        candidate_summary="test summary",
        fallback_read_rel="",
    )
    assert "probe=tcp_banner" in source
