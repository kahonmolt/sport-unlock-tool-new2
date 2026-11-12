"""
Decrypt a Simagic .sfu firmware package.

AES-256-CTR, key/IV hard-coded in simpro.exe (RVA 0x12C8730 / 0x12C8750),
counter = 16-byte big-endian, +1 per 16-byte block, applied to file[0x40:].

CTR is symmetric, so running this on a decrypted file re-encrypts it.

usage:  python decrypt_sfu.py <file.sfu> [-o out.bin] [--encrypt]
"""
import struct
import sys
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes.fromhex('2037df2888ab45f7841178e25d25998c'
                    '99aa34774383ee922234129833833284')
IV = bytes.fromhex('343413991235ddf3393899a1aa843299')


def crypt(buf, key=KEY, iv=IV):
    """XOR buf with the AES-256-CTR keystream starting at counter=iv."""
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    c = int.from_bytes(iv, 'big')
    out = bytearray()
    for i in range(0, len(buf), 16):
        ks = ecb.update((c + i // 16).to_bytes(16, 'big'))
        out += bytes(a ^ b for a, b in zip(buf[i:i + 16], ks))
    return bytes(out)


def parse_header(d):
    return {
        'magic': d[0x00:0x0C].decode('latin1'),
        'header_len': struct.unpack_from('<H', d, 0x0E)[0],
        'device': d[0x10:0x20].split(b'\x00')[0].decode('latin1'),
        'version': d[0x20:0x30].split(b'\x00')[0].decode('latin1'),
        'blob_len': struct.unpack_from('<I', d, 0x30)[0],
        'product_uuid': struct.unpack_from('<I', d, 0x34)[0],
        'board_uuid': struct.unpack_from('<I', d, 0x38)[0],
        'pid': struct.unpack_from('<H', d, 0x3C)[0],
        'vid': struct.unpack_from('<H', d, 0x3E)[0],
    }


def find_vector_table(d, limit=0x20000):
    for p in range(0, min(len(d) - 16, limit), 4):
        sp, rv = struct.unpack_from('<II', d, p)
        if (0x20000000 <= sp < 0x20100000 and sp & 3 == 0 and rv & 1
                and 0x08000000 <= rv < 0x08200000):
            return p, sp, rv
    return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    if not args:
        print(__doc__)
        return 1
    path = args[0]
    out = args[1] if len(args) > 1 else path.rsplit('.', 1)[0] + '.dec.bin'

    sfu = open(path, 'rb').read()
    if sfu[:12] != b'SIMPROSFU100':
        print('not a SIMPROSFU file')
        return 2

    plain = sfu[:0x40] + crypt(sfu[0x40:])
    open(out, 'wb').write(plain)

    h = parse_header(sfu)
    print('file      ', path)
    print('  magic    %s  header_len=%d' % (h['magic'], h['header_len']))
    print('  device   %s   version %s' % (h['device'], h['version']))
    print('  blob     0x%X (%d) bytes from 0x40' % (h['blob_len'], h['blob_len']))
    print('  uuid     product=0x%08X board=0x%08X pid=0x%04X vid=0x%04X'
          % (h['product_uuid'], h['board_uuid'], h['pid'], h['vid']))
    print('  record   %s | len=0x%X | digest=%s'
          % (plain[0x40:0x48].hex(),
             struct.unpack_from('<I', plain, 0x48)[0] if len(plain) > 0x4C else 0,
             plain[0x4C:0x60].hex()))
    vt = find_vector_table(plain)
    if vt:
        print('  vector   file 0x%X  SP=0x%08X  reset=0x%08X' % vt)
    else:
        print('  vector   none found (different MCU family, or wrong key)')
    print('  sha256   %s' % hashlib.sha256(plain).hexdigest())
    print('wrote', out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
