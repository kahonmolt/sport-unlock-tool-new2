"""Linear-disassemble .text and print instructions whose operand contains a given hex value."""
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
_, tva, tptr, traw = next(s for s in secs if s[0] == ".text")
code = data[tptr:tptr + traw]

needle = sys.argv[1] if len(sys.argv) > 1 else "0x13e4"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True
count = 0
for insn in md.disasm(code, tva):
    if needle in insn.op_str:
        print(f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}")
        count += 1
print(f"total: {count}")
