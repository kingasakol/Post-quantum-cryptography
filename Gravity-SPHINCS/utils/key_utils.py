from gravity_sphincs.aes import aesctr256
from gravity_sphincs.hash import Address, Hash
from gravity_sphincs.common import HASH_SIZE
from utils.bytes_utils import int_list_to_bytes


def gensk(key: Hash, address: Address, sk, key_size: int):
    iv = [None for _ in range(16)]
    for i in range(8):
        iv[i] = (address.index >> (56 - 8 * i)) & 0xFF
    for i in range(4):
        iv[i + 8] = (address.layer >> (24 - 8 * i)) & 0xFF
    for i in range(12, 16):
        iv[i] = 0

    out = aesctr256(key.to_bytes(), int_list_to_bytes(iv), key_size * HASH_SIZE)
    # out is now as bytes, need to convert to sk
    for i in range(key_size):
        for j in range(HASH_SIZE):
            sk.k[i].h[j] = out[i * HASH_SIZE + j]
