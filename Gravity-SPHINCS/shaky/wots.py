from finished.hash import hash_N_to_N_chain, Hash, Address
from common import WOTS_ell, HASH_SIZE
from finished.aes import aesctr256
from utils.hash_utlis import hash_to_bytes
from utils.bytes_utils import int_list_to_bytes


class Wots_SK:
    def __init__(self):
        self.k = [Hash() for _ in range(WOTS_ell)]


def wots_chain(src: Hash, count: int):
    dst = hash_N_to_N_chain(src, count)


def wots_gensk(key: Hash, address: Address, sk: Wots_SK):
    iv = [None for _ in range(16)]

    iv[0] = (address.index >> 56) & 0xFF
    iv[1] = (address.index >> 48) & 0xFF
    iv[2] = (address.index >> 40) & 0xFF
    iv[3] = (address.index >> 32) & 0xFF
    iv[4] = (address.index >> 24) & 0xFF
    iv[5] = (address.index >> 16) & 0xFF
    iv[6] = (address.index >> 8) & 0xFF
    iv[7] = address.index & 0xFF

    iv[8] = (address.layer >> 24) & 0xFF
    iv[9] = (address.layer >> 16) & 0xFF
    iv[10] = (address.layer >> 8) & 0xFF
    iv[11] = address.layer & 0xFF

    iv[12] = 0
    iv[13] = 0
    iv[14] = 0
    iv[15] = 0

    out = aesctr256(hash_to_bytes(key.h), int_list_to_bytes(iv), WOTS_ell * HASH_SIZE)
    # out is now as bytes, need to convert to wots sk
    for i in range(WOTS_ell):
        for j in range(HASH_SIZE):
            sk.k[i].h[j] = out[i * HASH_SIZE + j]


if __name__ == "__main__":
    print(WOTS_ell * HASH_SIZE)
