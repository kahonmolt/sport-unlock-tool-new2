"""Disassemble around given RVAs in simpro.exe."""
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
text_name, tva, tptr, traw = next(s for s in secs if s[0] == ".text")


def rva2off(rva):
    for name, va, ptr, raw in secs:
        if va <= rva < va + raw:
            return ptr + (rva - va)
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

marks = set()
for spec in sys.argv[1:]:
    if ":" not in spec:
        marks.add(int(spec, 0))

for spec in sys.argv[1:]:
    if ":" in spec:
        a, b = spec.split(":")
        lo, hi = int(a, 0), int(b, 0)
    else:
        lo = int(spec, 0) - 0x60
        hi = int(spec, 0) + 0x140
    off = rva2off(lo)
    code = data[off:off + (hi - lo)]
    print(f"\n===== 0x{lo:x} .. 0x{hi:x} =====")
    for insn in md.disasm(code, lo):
        mark = "  <<<" if insn.address in marks else ""
        print(f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}{mark}")
