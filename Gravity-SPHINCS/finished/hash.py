from shaky.common import HASH_SIZE
from finished.haraka import haraka256_256, haraka512_256, haraka256_256_chain
from utils.bytes_utils import int_list_to_bytes
import hashlib


class Hash:
    def __init__(self, h=None):
        if h:
            self.h = h
        else:
            self.h = [None for _ in range(HASH_SIZE)]  # uint8_t h[HASH_SIZE];


class Address:
    def __init__(self, index, layer):
        self.index = index
        self.layer = layer


def hashcmp(a, b):
    return hashcmpN(a, b, HASH_SIZE)


def hashcmpN(a, b, N):
    for i in range(16):
        if a.h[i] != b.h[i]:
            return False
    return True


def hashcpy(a: Hash, b: Hash):
    a.h = b.h.copy()


def hashcpyN(a: [Hash], b: [Hash], N: int):
    print("WARINING different than src")
    for i in range(N):
        a[i] = b[i]


def hashzero(a):
    a.h = [0 for _ in range(16)]


def hashswap(a: Hash, b: Hash):
    tmp = a.h
    a.h = b.h
    b.h = tmp


# not using dest
def hash_N_to_N(src):
    return haraka256_256(src.h)


def hash_N_to_N_chain(src: Hash, chinelen: int) -> Hash:
    return Hash(haraka256_256_chain(src.h, chinelen))


# takes two Hashes and makes haraka on them
def hash_2N_to_N(src1: Hash, src2: Hash) -> Hash:
    return Hash(haraka512_256(src1.h + src2.h))


# WARNING: accepts bytes!
def hash_to_N(src):
    s = int_list_to_bytes(src)
    h = hashlib.sha256()
    h.update(s)
    return h.digest()


# WORKS
def hash_compress_pairs(dst: [Hash], src: [Hash], count: int):
    for i in range(count):
        dst[i] = hash_2N_to_N(src[i*2], src[i*2+1])


def hash_compress_all(src):
    print("hash_compress_all WARNING: verify if ok")
    return [hash_to_N(s) for s in src]


def hash_parallel(src):
    print("hash_parallel WARNING: verify if ok")
    return [hash_N_to_N(s) for s in src]


def hash_parallel_chains(src: [Hash], chinelen: int) -> [Hash]:
    return [hash_N_to_N_chain(s, chinelen) for s in src]


if __name__ == "__main__":
    print(hash_to_N(bytes.fromhex("00" * 6)).hex())
    '''
    b0f66adc83641586656866813fd9dd0b8ebb63796075661ba45d1aa8089e1d44
    '''
    h1 = Hash()
    h2 = Hash()
    for i in range(HASH_SIZE):
        h1.h[i] = 60
        h2.h[i] = 9
    print(int_list_to_bytes(
        hash_2N_to_N(h1, h2).h).hex())  # 501b7e0d91defc20b7813d46a31838785af8a5aa21d86e57b92799d3bf178757
