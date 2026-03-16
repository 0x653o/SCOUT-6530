from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ELFHardening:
    nx: bool | None  # PT_GNU_STACK without PF_X → True (protected)
    pie: bool | None  # e_type == ET_DYN(3) → True
    relro: str | None  # "none"|"partial"|"full"
    canary: bool | None  # __stack_chk_fail symbol present → True
    stripped: bool | None  # .symtab section absent → True


# ELF constants
_ELF_MAGIC = b"\x7fELF"
_ELFCLASS32 = 1
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_ELFDATA2MSB = 2
_ET_DYN = 3

# Program header types
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PT_DYNAMIC = 2

# Program header flags
_PF_X = 0x1

# Section header types
_SHT_SYMTAB = 2
_SHT_DYNSYM = 11
_SHT_STRTAB = 3
_SHT_DYNAMIC = 6

# Dynamic tag types
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_NULL = 0

# Dynamic flag bits
_DF_BIND_NOW = 0x8


def parse_elf_hardening(path: Path) -> ELFHardening | None:
    """Parse ELF binary for security hardening properties.
    Returns None if not a valid ELF file."""
    try:
        with path.open("rb") as f:
            data = f.read()
    except OSError:
        return None

    if len(data) < 52 or data[:4] != _ELF_MAGIC:
        return None

    ei_class = data[4]
    ei_data = data[5]

    if ei_class not in (_ELFCLASS32, _ELFCLASS64):
        return None
    if ei_data not in (_ELFDATA2LSB, _ELFDATA2MSB):
        return None

    is_64 = ei_class == _ELFCLASS64
    endian = "<" if ei_data == _ELFDATA2LSB else ">"

    try:
        if is_64:
            # ELF64 header: e_type(2) e_machine(2) e_version(4) e_entry(8)
            # e_phoff(8) e_shoff(8) e_flags(4) e_ehsize(2) e_phentsize(2)
            # e_phnum(2) e_shentsize(2) e_shnum(2) e_shstrndx(2)
            if len(data) < 64:
                return None
            (e_type,) = struct.unpack_from(endian + "H", data, 16)
            (e_phoff,) = struct.unpack_from(endian + "Q", data, 32)
            (e_shoff,) = struct.unpack_from(endian + "Q", data, 40)
            (e_phentsize,) = struct.unpack_from(endian + "H", data, 54)
            (e_phnum,) = struct.unpack_from(endian + "H", data, 56)
            (e_shentsize,) = struct.unpack_from(endian + "H", data, 58)
            (e_shnum,) = struct.unpack_from(endian + "H", data, 60)
            (e_shstrndx,) = struct.unpack_from(endian + "H", data, 62)
        else:
            # ELF32 header
            if len(data) < 52:
                return None
            (e_type,) = struct.unpack_from(endian + "H", data, 16)
            (e_phoff,) = struct.unpack_from(endian + "I", data, 28)
            (e_shoff,) = struct.unpack_from(endian + "I", data, 32)
            (e_phentsize,) = struct.unpack_from(endian + "H", data, 42)
            (e_phnum,) = struct.unpack_from(endian + "H", data, 44)
            (e_shentsize,) = struct.unpack_from(endian + "H", data, 46)
            (e_shnum,) = struct.unpack_from(endian + "H", data, 48)
            (e_shstrndx,) = struct.unpack_from(endian + "H", data, 50)
    except struct.error:
        return None

    # --- PIE ---
    pie = e_type == _ET_DYN

    # --- Parse program headers ---
    nx: bool | None = None
    has_gnu_relro = False
    has_bind_now = False
    dynamic_offset: int | None = None
    dynamic_size: int | None = None

    if e_phoff > 0 and e_phnum > 0 and e_phentsize > 0:
        for i in range(e_phnum):
            ph_start = e_phoff + i * e_phentsize
            try:
                if is_64:
                    # Phdr64: p_type(4) p_flags(4) p_offset(8) ...
                    if ph_start + 56 > len(data):
                        break
                    (p_type,) = struct.unpack_from(endian + "I", data, ph_start)
                    (p_flags,) = struct.unpack_from(endian + "I", data, ph_start + 4)
                    (p_offset,) = struct.unpack_from(endian + "Q", data, ph_start + 8)
                    # p_vaddr(8) p_paddr(8) p_filesz(8) p_memsz(8) p_align(8)
                    (p_filesz,) = struct.unpack_from(endian + "Q", data, ph_start + 32)
                else:
                    # Phdr32: p_type(4) p_offset(4) p_vaddr(4) p_paddr(4)
                    # p_filesz(4) p_memsz(4) p_flags(4) p_align(4)
                    if ph_start + 32 > len(data):
                        break
                    (p_type,) = struct.unpack_from(endian + "I", data, ph_start)
                    (p_offset,) = struct.unpack_from(endian + "I", data, ph_start + 4)
                    (p_filesz,) = struct.unpack_from(endian + "I", data, ph_start + 16)
                    (p_flags,) = struct.unpack_from(endian + "I", data, ph_start + 24)
            except struct.error:
                break

            if p_type == _PT_GNU_STACK:
                nx = not bool(p_flags & _PF_X)
            elif p_type == _PT_GNU_RELRO:
                has_gnu_relro = True
            elif p_type == _PT_DYNAMIC:
                dynamic_offset = p_offset
                dynamic_size = p_filesz

    # --- RELRO ---
    # Check for DT_BIND_NOW / DF_BIND_NOW in .dynamic segment
    if has_gnu_relro and dynamic_offset is not None and dynamic_size is not None:
        dyn_end = dynamic_offset + dynamic_size
        if dyn_end <= len(data):
            pos = dynamic_offset
            while pos < dyn_end:
                try:
                    if is_64:
                        if pos + 16 > dyn_end:
                            break
                        (d_tag,) = struct.unpack_from(endian + "q", data, pos)
                        (d_val,) = struct.unpack_from(endian + "Q", data, pos + 8)
                        pos += 16
                    else:
                        if pos + 8 > dyn_end:
                            break
                        (d_tag,) = struct.unpack_from(endian + "i", data, pos)
                        (d_val,) = struct.unpack_from(endian + "I", data, pos + 4)
                        pos += 8
                except struct.error:
                    break

                if d_tag == _DT_NULL:
                    break
                if d_tag == _DT_BIND_NOW:
                    has_bind_now = True
                elif d_tag == _DT_FLAGS and (d_val & _DF_BIND_NOW):
                    has_bind_now = True

    if has_gnu_relro and has_bind_now:
        relro: str | None = "full"
    elif has_gnu_relro:
        relro = "partial"
    else:
        relro = "none"

    # --- Parse section headers for canary and stripped ---
    canary: bool | None = None
    stripped: bool | None = None
    has_symtab = False

    # Find .shstrtab for section name lookup, and scan sections
    dynstr_data: bytes = b""

    if e_shoff > 0 and e_shnum > 0 and e_shentsize > 0:
        # First, get the section name string table
        shstrtab_data: bytes = b""
        if e_shstrndx < e_shnum:
            shstr_sh_start = e_shoff + e_shstrndx * e_shentsize
            try:
                if is_64:
                    (sh_offset,) = struct.unpack_from(endian + "Q", data, shstr_sh_start + 24)
                    (sh_size,) = struct.unpack_from(endian + "Q", data, shstr_sh_start + 32)
                else:
                    (sh_offset,) = struct.unpack_from(endian + "I", data, shstr_sh_start + 16)
                    (sh_size,) = struct.unpack_from(endian + "I", data, shstr_sh_start + 20)
                if sh_offset + sh_size <= len(data):
                    shstrtab_data = data[sh_offset : sh_offset + sh_size]
            except struct.error:
                pass

        for i in range(e_shnum):
            sh_start = e_shoff + i * e_shentsize
            try:
                if is_64:
                    if sh_start + 64 > len(data):
                        break
                    (sh_name,) = struct.unpack_from(endian + "I", data, sh_start)
                    (sh_type,) = struct.unpack_from(endian + "I", data, sh_start + 4)
                    (sh_offset,) = struct.unpack_from(endian + "Q", data, sh_start + 24)
                    (sh_size,) = struct.unpack_from(endian + "Q", data, sh_start + 32)
                else:
                    if sh_start + 40 > len(data):
                        break
                    (sh_name,) = struct.unpack_from(endian + "I", data, sh_start)
                    (sh_type,) = struct.unpack_from(endian + "I", data, sh_start + 4)
                    (sh_offset,) = struct.unpack_from(endian + "I", data, sh_start + 16)
                    (sh_size,) = struct.unpack_from(endian + "I", data, sh_start + 20)
            except struct.error:
                break

            if sh_type == _SHT_SYMTAB:
                has_symtab = True
            elif sh_type == _SHT_STRTAB:
                # Check if this is .dynstr by name
                if shstrtab_data and sh_name < len(shstrtab_data):
                    name_end = shstrtab_data.find(b"\x00", sh_name)
                    sec_name = shstrtab_data[sh_name:name_end] if name_end >= 0 else b""
                    if sec_name == b".dynstr":
                        if sh_offset + sh_size <= len(data):
                            dynstr_data = data[sh_offset : sh_offset + sh_size]

    stripped = not has_symtab

    # --- Canary: search for __stack_chk_fail in .dynstr or fallback whole binary ---
    if dynstr_data:
        canary = b"__stack_chk_fail" in dynstr_data
    else:
        # Fallback: search in entire binary data (less precise)
        canary = b"__stack_chk_fail" in data

    return ELFHardening(
        nx=nx,
        pie=pie,
        relro=relro,
        canary=canary,
        stripped=stripped,
    )
