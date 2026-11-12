import os, sys, numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.insert(0, r'C:\projects\simagic-evo-sport-modification\tools')
from aessweep import sweep

TMP = r'C:\Users\Player1\AppData\Local\Temp\opencode'
SFU = (r'C:\Users\Player1\AppData\Local\SIMAGIC\firmware\base\alpha_evo1'
       r'\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu')

key = bytes.fromhex('deadbeef01234567deadbeef89abcdef')
arm = (bytes.fromhex('00000220') + bytes.fromhex('c5e70008') +
       bytes.fromhex('11223308') + bytes.fromhex('55667708'))
ct = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(arm)

sfu = bytearray(open(SFU, 'rb').read())
sfu[0x100:0x110] = ct
p = os.path.join(TMP, 'test.sfu')
open(p, 'wb').write(bytes(sfu))

# synthetic binary: filler + key at a known offset
binpath = os.path.join(TMP, 'test.bin')
blob = bytearray(os.urandom(100000))
off = 50000
blob[off:off + 16] = key
open(binpath, 'wb').write(bytes(blob))

total, hits = sweep(binpath, os.path.join(TMP, 'test.hits.txt'), p,
                    keylens=((16, 10, 'AES-128'),), chunk=100000)
print('expected 1 hit, got', hits)
print(open(os.path.join(TMP, 'test.hits.txt')).read())
