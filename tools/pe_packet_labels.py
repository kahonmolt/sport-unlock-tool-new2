"""For each 4-byte HID packet builder, list log strings referenced nearby."""
import re
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
_, tva, tptr, traw = next(s for s in secs if s[0] == ".text")
code = data[tptr:tptr + traw]

def rva2off(rva):
    for name, va, ptr, raw in secs:
        if va <= rva < va + raw:
            return ptr + (rva - va)
    return None

def cstr(rva, n=90):
    o = rva2off(rva)
    if o is None:
        return ""
    b = data[o:o + n]
    out = []
    for c in b:
        if 32 <= c < 127:
            out.append(chr(c))
        else:
            break
    s = "".join(out)
    return s if len(s) >= 5 else ""

pat = re.compile(rb"\xc6\x00(.)(?:.{0,40}?)\xc6\x40\x01(.)(?:.{0,40}?)\xc6\x40\x02(.)(?:.{0,40}?)\xc6\x40\x03(.)", re.S)
sites = []
for m in pat.finditer(code):
    sites.append((tva + m.start(), m.group(1)[0], m.group(2)[0], m.group(3)[0], m.group(4)[0]))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for rva, rid, b1, b2, b3 in sites:
    lo = rva - 0x500
    off = rva2off(lo)
    chunk = data[off:off + 0x520]
    strings = []
    for insn in md.disasm(chunk, lo):
        if insn.mnemonic == "lea" and insn.operands and insn.operands[1].type == X86_OP_MEM and insn.operands[1].mem.base == X86_REG_RIP:
            tgt = insn.address + insn.size + insn.operands[1].mem.disp
            s = cstr(tgt)
            if s:
                strings.append(s)
    # function start: last CC CC before site
    j = rva - tva
    while j > 0 and not (code[j - 1] == 0xCC and code[j - 2] == 0xCC):
        j -= 1
    uniq = list(dict.fromkeys(strings))
    print(f"\n0x{rva:06x}  {rid:02x} {b1:02x} {b2:02x} {b3:02x}  func~0x{tva + j:06x}")
    for s in uniq[:10]:
        print(f"    {s}")
