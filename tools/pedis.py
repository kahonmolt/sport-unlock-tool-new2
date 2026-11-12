"""Disassemble a range of the PE and annotate RIP-relative data references with ASCII strings."""
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP

p = sys.argv[1]
start = int(sys.argv[2], 0)
end = int(sys.argv[3], 0)
pe = pefile.PE(p, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
d = open(p, 'rb').read()
secs = [(s.Name.decode().rstrip('\x00'), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]

def rva2off(rva):
    for name, va, ptr, raw in secs:
        if va <= rva < va + raw:
            return ptr + (rva - va)
    return None

def read_str(rva, maxlen=80):
    o = rva2off(rva)
    if o is None:
        return None
    b = d[o:o + maxlen]
    out = bytearray()
    for c in b:
        if 32 <= c < 127:
            out.append(c)
        else:
            break
    if len(out) >= 4:
        return out.decode('latin1')
    return None

off = rva2off(start)
code = d[off:off + (end - start)]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for ins in md.disasm(code, base + start):
    annot = ''
    if ins.id:
        for op in ins.operands:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                s = read_str(tgt - base)
                if s:
                    annot = '   ; "%s"' % s
                else:
                    annot = '   ; rva %x' % (tgt - base)
    print('%08x  %-7s %s%s' % (ins.address - base, ins.mnemonic, ins.op_str, annot))
