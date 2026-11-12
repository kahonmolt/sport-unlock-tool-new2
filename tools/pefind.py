"""Locate RIP-relative references in a PE image to a set of target RVAs."""
import sys, struct, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP
import pefile

def load(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = open(path, 'rb').read()
    secs = []
    for s in pe.sections:
        name = s.Name.decode().rstrip('\x00')
        secs.append((name, s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, s.Misc_VirtualSize))
    return pe, base, data, secs

def off2rva(secs, off):
    for name, va, ptr, raw, vsz in secs:
        if ptr <= off < ptr + raw:
            return va + (off - ptr)
    return None

def rva2off(secs, rva):
    for name, va, ptr, raw, vsz in secs:
        if va <= rva < va + max(raw, vsz):
            return ptr + (rva - va)
    return None

def main():
    path = sys.argv[1]
    targets = [int(x, 0) for x in sys.argv[2:]]
    pe, base, data, secs = load(path)
    text = next(s for s in secs if s[0] == '.text')
    name, va, ptr, raw, vsz = text
    code = data[ptr:ptr + raw]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    tset = set(targets)
    hits = []
    for ins in md.disasm(code, base + va):
        for op in ins.operands:
            tgt = None
            if op.type == CS_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                pass
            # rip-relative: mem.base == X86_REG_RIP
            if op.type == CS_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    tgt = ins.address + ins.size + op.mem.disp
                elif op.mem.base == 0 and op.mem.index == 0 and op.mem.disp > 0:
                    tgt = op.mem.disp
            if tgt is None:
                continue
            rv = tgt - base
            if rv in tset:
                hits.append((ins.address - base, ins.mnemonic, ins.op_str))
    for rva, mn, ops in hits:
        print(f'{rva:08x}  {mn} {ops}')

if __name__ == '__main__':
    main()
