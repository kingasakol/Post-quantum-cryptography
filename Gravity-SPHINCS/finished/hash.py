from common import HASH_SIZE
from finished.haraka import haraka256_256, haraka512_256, haraka256_256_chain
from finished.python_utils import int_list_to_bytes, bytes_to_int_list
import hashlib


class Hash:
    def __init__(self):
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


def hashcpy(a, b):
    a.h = b.h.copy()


def hashcpyN(a, b, N):
    for i in range(N):
        a.h[i] = b.h[i]


def hashzero(a):
    a.h = [0 for _ in range(16)]


def hashswap(a, b):
    tmp = a.h
    a.h = b.h
    b.h = tmp


# not using dest
def hash_N_to_N(src):
    return haraka256_256(src.h)


def hash_N_to_N_chain(src, chinelen):
    return haraka256_256_chain(src.h, chinelen)


def hash_2N_to_N(src):
    return haraka512_256(src.h)


# WARNING: accepts bytes!
def hash_to_N(src):
    s = int_list_to_bytes(src)
    h = hashlib.sha256()
    h.update(s)
    return h.digest()


# TODO verify
def hash_compress_pairs(src):
    print("hash_compress_pairs WARNING: verify if ok")
    return [hash_2N_to_N(s) for s in src]


def hash_compress_all(src):
    print("hash_compress_all WARNING: verify if ok")
    return [hash_to_N(s) for s in src]


def hash_parallel(src):
    print("hash_parallel WARNING: verify if ok")
    return [hash_N_to_N(s) for s in src]


def hash_parallel_chains(src, chinelen):
    print("hash_parallel_chains WARNING: verify if ok")
    return [hash_N_to_N_chain(s, chinelen) for s in src]


if __name__ == "__main__":
    print(hash_to_N(bytes.fromhex("00" * 6)).hex())
    '''
    b0f66adc83641586656866813fd9dd0b8ebb63796075661ba45d1aa8089e1d44
    '''
