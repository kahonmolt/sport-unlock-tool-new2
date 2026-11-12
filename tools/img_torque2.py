import struct, collections

IMG = r'C:\projects\simagic-evo-sport-modification\tools\Alpha_Evo_Sport_decrypted.bin'
BASE = 0x240
d = open(IMG, 'rb').read()
img = d[BASE:]

def hexdump(off, n, base=BASE):
    for r in range(off, off + n, 16):
        if r + 16 > len(img):
            break
        h = img[r:r + 16].hex(' ')
        a = ''.join(chr(c) if 32 <= c < 127 else '.' for c in img[r:r + 16])
        print('  %06X  %s  %s' % (r + base, h, a))

print('== zero-filled block 0x282A0..0x28700 ==')
hexdump(0x282A0 - BASE, 0x180)

print('\n== context around float 100.0 sites ==')
for off in (0x8ae0, 0x11854, 0x278d4, 0x2acd8, 0x2bfd8, 0x2bffc, 0x2ddcc):
    o = off - BASE
    print(' 0x%06X: %s' % (off, img[o - 16:o + 16].hex(' ')))

print('\n== 32-bit literal 9 / 12 occurrences (count only) ==')
for v in (9, 12, 10, 15, 18, 21):
    pat = struct.pack('<I', v)
    locs = [i + BASE for i in range(0, len(img) - 3, 4) if img[i:i + 4] == pat]
    print('  u32 %-3d x%-4d %s' % (v, len(locs), [hex(x) for x in locs[:10]]))

print('\n== 16-bit 9 / 12 occurrences (count only) ==')
for v in (9, 12):
    pat = struct.pack('<H', v)
    locs = [i + BASE for i in range(0, len(img) - 1, 2) if img[i:i + 2] == pat]
    print('  u16 %-3d x%-4d %s' % (v, len(locs), [hex(x) for x in locs[:10]]))

print('\n== per-64B density of 0x00 (find data-like islands) ==')
best = []
for r in range(0, len(img) - 64, 64):
    seg = img[r:r + 64]
    z = seg.count(0)
    if z >= 32:
        best.append((r + BASE, z))
print('  blocks with >=50%% zeros:', len(best))
for o, z in best[:20]:
    print('   0x%06X  zeros=%d/64' % (o, z))

print('\n== last 0x800 bytes ==')
hexdump(len(img) - 0x800, 0x800)
