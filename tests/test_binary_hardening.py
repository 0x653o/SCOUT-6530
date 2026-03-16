from __future__ import annotations

import struct
from pathlib import Path

from aiedge.binary_hardening import ELFHardening, parse_elf_hardening


def _build_elf(
    *,
    bits: int = 64,
    endian: str = "little",
    e_type: int = 3,  # ET_DYN
    program_headers: list[tuple[int, int, int, int, int]] | None = None,
    sections: list[tuple[bytes, int, bytes]] | None = None,
    dynstr_content: bytes | None = None,
    include_symtab: bool = False,
) -> bytes:
    """Build a minimal ELF binary for testing.

    program_headers: list of (p_type, p_flags, p_offset, p_filesz, p_memsz)
    sections: list of (name, sh_type, data) -- names added to shstrtab
    dynstr_content: if set, a .dynstr section is auto-added
    include_symtab: if True, adds a SHT_SYMTAB section header
    """
    is_64 = bits == 64
    fmt = "<" if endian == "little" else ">"

    section_defs: list[tuple[int, int, bytes]] = []  # (name_offset, sh_type, data)

    # Build section name string table
    name_offset_map: dict[bytes, int] = {}
    strtab = bytearray(b"\x00")

    def add_name(name: bytes) -> int:
        if name in name_offset_map:
            return name_offset_map[name]
        offset = len(strtab)
        strtab.extend(name + b"\x00")
        name_offset_map[name] = offset
        return offset

    shstrtab_name_off = add_name(b".shstrtab")

    if dynstr_content is not None:
        dynstr_name_off = add_name(b".dynstr")
        section_defs.append((dynstr_name_off, 3, dynstr_content))  # SHT_STRTAB=3

    if sections:
        for name, sh_type, data in sections:
            off = add_name(name)
            section_defs.append((off, sh_type, data))

    if include_symtab:
        symtab_name_off = add_name(b".symtab")
        section_defs.append((symtab_name_off, 2, b"\x00" * 24))  # SHT_SYMTAB=2

    shstrtab_data = bytes(strtab)

    # Program headers
    phdrs = program_headers or []
    e_phnum = len(phdrs)

    # Section headers: null + user sections + shstrtab
    e_shnum = 1 + len(section_defs) + 1
    e_shstrndx = e_shnum - 1

    if is_64:
        ehdr_size = 64
        phdr_size = 56
        shdr_size = 64
    else:
        ehdr_size = 52
        phdr_size = 32
        shdr_size = 40

    e_phoff = ehdr_size if phdrs else 0
    data_start = ehdr_size + phdr_size * e_phnum

    # Layout section data
    section_data_offsets: list[int] = []
    section_data_list: list[bytes] = []
    current_offset = data_start
    for _, _, sdata in section_defs:
        section_data_offsets.append(current_offset)
        section_data_list.append(sdata)
        current_offset += len(sdata)

    # shstrtab data
    shstrtab_offset = current_offset
    current_offset += len(shstrtab_data)

    # Section headers come after all data
    e_shoff = current_offset

    # Build ELF header
    ei_class = 2 if is_64 else 1
    ei_data = 1 if endian == "little" else 2
    e_ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8

    if is_64:
        ehdr = struct.pack(
            fmt + "16sHHIQQQIHHHHHH",
            e_ident,
            e_type, 0x3E, 1, 0,
            e_phoff, e_shoff, 0,
            ehdr_size, phdr_size, e_phnum,
            shdr_size, e_shnum, e_shstrndx,
        )
    else:
        ehdr = struct.pack(
            fmt + "16sHHIIIIIHHHHHH",
            e_ident,
            e_type, 0x28, 1, 0,
            e_phoff, e_shoff, 0,
            ehdr_size, phdr_size, e_phnum,
            shdr_size, e_shnum, e_shstrndx,
        )

    # Build program headers
    phdr_bytes = b""
    for p_type, p_flags, p_offset, p_filesz, p_memsz in phdrs:
        if is_64:
            phdr_bytes += struct.pack(
                fmt + "IIQQQQQQ",
                p_type, p_flags, p_offset,
                0, 0, p_filesz, p_memsz, 0,
            )
        else:
            phdr_bytes += struct.pack(
                fmt + "IIIIIIII",
                p_type, p_offset, 0, 0,
                p_filesz, p_memsz, p_flags, 0,
            )

    # Section data
    all_data = b""
    for sdata in section_data_list:
        all_data += sdata
    all_data += shstrtab_data

    # Build section headers
    if is_64:
        null_shdr = struct.pack(fmt + "IIQQQQIIqq", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    else:
        null_shdr = struct.pack(fmt + "IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    shdrs = null_shdr
    for idx, (name_off, sh_type, sdata) in enumerate(section_defs):
        if is_64:
            shdrs += struct.pack(
                fmt + "IIQQQQIIqq",
                name_off, sh_type, 0, 0,
                section_data_offsets[idx], len(sdata),
                0, 0, 1, 0,
            )
        else:
            shdrs += struct.pack(
                fmt + "IIIIIIIIII",
                name_off, sh_type, 0, 0,
                section_data_offsets[idx], len(sdata),
                0, 0, 1, 0,
            )

    # shstrtab section header
    if is_64:
        shdrs += struct.pack(
            fmt + "IIQQQQIIqq",
            shstrtab_name_off, 3, 0, 0,
            shstrtab_offset, len(shstrtab_data),
            0, 0, 1, 0,
        )
    else:
        shdrs += struct.pack(
            fmt + "IIIIIIIIII",
            shstrtab_name_off, 3, 0, 0,
            shstrtab_offset, len(shstrtab_data),
            0, 0, 1, 0,
        )

    return ehdr + phdr_bytes + all_data + shdrs


def _build_dynamic_section(
    entries: list[tuple[int, int]], *, bits: int = 64, endian: str = "little"
) -> bytes:
    """Build a .dynamic section from (tag, value) pairs. Appends DT_NULL."""
    fmt = "<" if endian == "little" else ">"
    data = b""
    for tag, val in entries:
        if bits == 64:
            data += struct.pack(fmt + "qQ", tag, val)
        else:
            data += struct.pack(fmt + "iI", tag, val)
    # DT_NULL terminator
    if bits == 64:
        data += struct.pack(fmt + "qQ", 0, 0)
    else:
        data += struct.pack(fmt + "iI", 0, 0)
    return data


# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------


def test_non_elf_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "not_elf"
    p.write_bytes(b"This is not an ELF file at all")
    assert parse_elf_hardening(p) is None


def test_empty_file_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert parse_elf_hardening(p) is None


def test_missing_file_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "does_not_exist"
    assert parse_elf_hardening(p) is None


def test_minimal_64bit_elf(tmp_path: Path) -> None:
    data = _build_elf(bits=64, e_type=3)
    p = tmp_path / "test64.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.pie is True
    assert result.stripped is True


def test_minimal_32bit_elf(tmp_path: Path) -> None:
    data = _build_elf(bits=32, e_type=3)
    p = tmp_path / "test32.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.pie is True
    assert result.stripped is True


def test_nx_enabled_with_gnu_stack_no_exec(tmp_path: Path) -> None:
    """PT_GNU_STACK with p_flags=6 (RW, no X) -> NX enabled."""
    data = _build_elf(
        bits=64,
        program_headers=[
            (0x6474E551, 0x6, 0, 0, 0),  # PT_GNU_STACK, PF_R|PF_W
        ],
    )
    p = tmp_path / "nx_on.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is True


def test_nx_disabled_with_gnu_stack_exec(tmp_path: Path) -> None:
    """PT_GNU_STACK with p_flags=7 (RWX) -> NX disabled."""
    data = _build_elf(
        bits=64,
        program_headers=[
            (0x6474E551, 0x7, 0, 0, 0),  # PF_R|PF_W|PF_X
        ],
    )
    p = tmp_path / "nx_off.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is False


def test_nx_none_without_gnu_stack(tmp_path: Path) -> None:
    """No PT_GNU_STACK -> nx is None."""
    data = _build_elf(bits=64, program_headers=[])
    p = tmp_path / "no_stack.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is None


def test_pie_et_dyn(tmp_path: Path) -> None:
    data = _build_elf(bits=64, e_type=3)
    p = tmp_path / "pie.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.pie is True


def test_no_pie_et_exec(tmp_path: Path) -> None:
    data = _build_elf(bits=64, e_type=2)
    p = tmp_path / "no_pie.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.pie is False


def test_relro_none(tmp_path: Path) -> None:
    """No PT_GNU_RELRO -> relro='none'."""
    data = _build_elf(bits=64, program_headers=[])
    p = tmp_path / "no_relro.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.relro == "none"


def test_relro_partial(tmp_path: Path) -> None:
    """PT_GNU_RELRO present but no BIND_NOW -> partial."""
    data = _build_elf(
        bits=64,
        program_headers=[
            (0x6474E552, 0x4, 0, 0, 0),  # PT_GNU_RELRO
        ],
    )
    p = tmp_path / "partial_relro.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.relro == "partial"


def test_relro_full_with_bind_now(tmp_path: Path) -> None:
    """PT_GNU_RELRO + DT_BIND_NOW in .dynamic -> full."""
    dyn_section_data = _build_dynamic_section([(24, 0)], bits=64)
    # No dynstr, so .dynamic is the first section; data starts after ehdr+2*phdr
    data_offset = 64 + 56 * 2

    raw = _build_elf(
        bits=64,
        program_headers=[
            (0x6474E552, 0x4, 0, 0, 0),
            (2, 0x6, data_offset, len(dyn_section_data), len(dyn_section_data)),
        ],
        sections=[(b".dynamic", 6, dyn_section_data)],
    )
    p = tmp_path / "full_relro.elf"
    p.write_bytes(raw)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.relro == "full"


def test_relro_full_with_df_bind_now(tmp_path: Path) -> None:
    """PT_GNU_RELRO + DT_FLAGS with DF_BIND_NOW -> full."""
    dyn_data = _build_dynamic_section([(30, 0x8)], bits=64)
    data_offset = 64 + 56 * 2

    raw = _build_elf(
        bits=64,
        program_headers=[
            (0x6474E552, 0x4, 0, 0, 0),
            (2, 0x6, data_offset, len(dyn_data), len(dyn_data)),
        ],
        sections=[(b".dynamic", 6, dyn_data)],
    )
    p = tmp_path / "full_relro_df.elf"
    p.write_bytes(raw)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.relro == "full"


def test_canary_present(tmp_path: Path) -> None:
    """__stack_chk_fail in .dynstr -> canary=True."""
    dynstr = b"\x00__stack_chk_fail\x00printf\x00"
    data = _build_elf(bits=64, dynstr_content=dynstr)
    p = tmp_path / "canary.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.canary is True


def test_canary_absent(tmp_path: Path) -> None:
    """No __stack_chk_fail -> canary=False."""
    dynstr = b"\x00printf\x00puts\x00"
    data = _build_elf(bits=64, dynstr_content=dynstr)
    p = tmp_path / "no_canary.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.canary is False


def test_stripped(tmp_path: Path) -> None:
    """No SHT_SYMTAB -> stripped=True."""
    data = _build_elf(bits=64, include_symtab=False)
    p = tmp_path / "stripped.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.stripped is True


def test_not_stripped(tmp_path: Path) -> None:
    """With SHT_SYMTAB -> stripped=False."""
    data = _build_elf(bits=64, include_symtab=True)
    p = tmp_path / "not_stripped.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.stripped is False


def test_32bit_nx_and_pie(tmp_path: Path) -> None:
    """32-bit ELF with NX and PIE."""
    data = _build_elf(
        bits=32, e_type=3,
        program_headers=[(0x6474E551, 0x6, 0, 0, 0)],
    )
    p = tmp_path / "test32_nx_pie.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is True
    assert result.pie is True


def test_big_endian_elf(tmp_path: Path) -> None:
    """Big-endian ELF parsing."""
    data = _build_elf(
        bits=64, endian="big", e_type=3,
        program_headers=[(0x6474E551, 0x6, 0, 0, 0)],
    )
    p = tmp_path / "big_endian.elf"
    p.write_bytes(data)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is True
    assert result.pie is True


def test_fully_hardened_elf(tmp_path: Path) -> None:
    """ELF with all protections: NX, PIE, full RELRO, canary, not stripped."""
    dynstr = b"\x00__stack_chk_fail\x00"
    dyn_data = _build_dynamic_section([(24, 0)], bits=64)
    # data_start = ehdr(64) + 3*phdr(56) = 232
    # dynstr is first section (added by dynstr_content), then .dynamic, then .symtab
    # .dynamic offset = 232 + len(dynstr)
    data_start = 64 + 56 * 3
    dyn_offset = data_start + len(dynstr)

    raw = _build_elf(
        bits=64, e_type=3,
        program_headers=[
            (0x6474E551, 0x6, 0, 0, 0),
            (0x6474E552, 0x4, 0, 0, 0),
            (2, 0x6, dyn_offset, len(dyn_data), len(dyn_data)),
        ],
        sections=[(b".dynamic", 6, dyn_data)],
        dynstr_content=dynstr,
        include_symtab=True,
    )
    p = tmp_path / "fully_hardened.elf"
    p.write_bytes(raw)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is True
    assert result.pie is True
    assert result.relro == "full"
    assert result.canary is True
    assert result.stripped is False


def test_no_protections_elf(tmp_path: Path) -> None:
    """ELF with no protections."""
    dynstr = b"\x00printf\x00"
    raw = _build_elf(
        bits=64, e_type=2,
        program_headers=[(0x6474E551, 0x7, 0, 0, 0)],
        dynstr_content=dynstr,
        include_symtab=False,
    )
    p = tmp_path / "no_protections.elf"
    p.write_bytes(raw)
    result = parse_elf_hardening(p)
    assert result is not None
    assert result.nx is False
    assert result.pie is False
    assert result.relro == "none"
    assert result.canary is False
    assert result.stripped is True
