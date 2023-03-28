from finished.aes import aesctr256
from finished.hash import Address, Hash
from shaky.common import HASH_SIZE
from utils.bytes_utils import int_list_to_bytes
from utils.hash_utlis import hash_to_bytes


def gensk(key: Hash, address: Address, sk, key_size: int):
    iv = [None for _ in range(16)]
    for i in range(8):
        iv[i] = (address.index >> (56 - 8 * i)) & 0xFF
    for i in range(4):
        iv[i + 8] = (address.layer >> (24 - 8 * i)) & 0xFF
    for i in range(12, 16):
        iv[i] = 0

    out = aesctr256(hash_to_bytes(key), int_list_to_bytes(iv), key_size * HASH_SIZE)
    # out is now as bytes, need to convert to sk
    for i in range(key_size):
        for j in range(HASH_SIZE):
            sk.k[i].h[j] = out[i * HASH_SIZE + j]