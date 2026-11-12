import sys, numpy as np
sys.path.insert(0, r'C:\projects\simagic-evo-sport-modification\tools')
import importlib.util
spec = importlib.util.spec_from_file_location('aessweep', r'C:\projects\simagic-evo-sport-modification\tools\aessweep.py')
m = importlib.util.module_from_spec(spec)
# prevent main() from running
src = open(r'C:\projects\simagic-evo-sport-modification\tools\aessweep.py').read().replace("if __name__ == '__main__':\n    main()", "")
exec(compile(src, 'aessweep', 'exec'), m.__dict__)

from aessweep import expand_key, decrypt_block, SBOX, MUL

# Build a synthetic plaintext that looks like an ARM vector table, encrypt it under
# a random key (implement encryption by inverting the decrypt path is messy, so use
# a round-trip: decrypt a random ciphertext then re-encrypt via openssl-equivalent)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex('00112233445566778899aabbccddeeff')
arm = bytes.fromhex('00000220') + bytes.fromhex('c5e70008') + bytes.fromhex('11223308') + bytes.fromhex('55667708')
ct = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(arm)
print('synthetic ct', ct.hex())

rk = expand_key(np.frombuffer(key, dtype=np.uint8).reshape(1, 16), 10)
pt = decrypt_block(rk, np.frombuffer(ct, dtype=np.uint8).reshape(1, 16), 10)
print('decrypt ->', bytes(pt[0]).hex(), 'match' if bytes(pt[0]) == arm else 'MISMATCH')

# AES-256 round trip
key2 = bytes(range(32))
ct2 = Cipher(algorithms.AES(key2), modes.ECB()).encryptor().update(arm)
rk2 = expand_key(np.frombuffer(key2, dtype=np.uint8).reshape(1, 32), 14)
pt2 = decrypt_block(rk2, np.frombuffer(ct2, dtype=np.uint8).reshape(1, 16), 14)
print('aes256 decrypt ->', bytes(pt2[0]).hex(), 'match' if bytes(pt2[0]) == arm else 'MISMATCH')
