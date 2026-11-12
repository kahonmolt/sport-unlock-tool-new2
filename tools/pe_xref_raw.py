"""Find pointer references (absolute, RVA-relative, or RIP-relative) to a target RVA."""
import struct
import sys

import pefile

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, s.Misc_VirtualSize)
        for s in pe.sections]

target = int(sys.argv[1], 0)
print(f"image base 0x{base:x}, target RVA 0x{target:x}")

def off2rva(off):
    for name, va, ptr, raw, vsz in secs:
        if ptr <= off < ptr + raw:
            return name, va + (off - ptr)
    return None, None

def rva2off(rva):
    for name, va, ptr, raw, vsz in secs:
        if va <= rva < va + max(raw, vsz):
            return ptr + (rva - va)
    return None

# 1. absolute pointers
for size, fmt in ((8, "<Q"), (4, "<I")):
    needle = struct.pack(fmt, (base + target) if size == 8 else target)
    start = 0
    hits = []
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        sec, rva = off2rva(i)
        if sec in (".rdata", ".data", ".pdata", ".reloc") or i % 4 == 0:
            hits.append((i, sec, rva))
        start = i + 1
    print(f"{size}-byte matches: {len(hits)}")
    for i, sec, rva in hits[:20]:
        print(f"  off=0x{i:x} sec={sec} rva={hex(rva) if rva else None}")

# 2. RIP-relative scan over .text, every byte offset (no disassembly assumption)
text = next(s for s in secs if s[0] == ".text")
name, tva, tptr, traw, tvsz = text
code = data[tptr:tptr + traw]
print("\nRIP-relative candidates (any instruction length 4..10):")
found = 0
for i in range(len(code) - 4):
    disp = struct.unpack_from("<i", code, i)[0]
    insn_end = tva + i + 4
    if insn_end + disp == target:
        found += 1
        if found <= 30:
            print(f"  file=0x{tptr+i:x} rva=0x{tva+i:x} disp=0x{disp:x}")
print(f"total raw rip-relative candidates: {found}")
