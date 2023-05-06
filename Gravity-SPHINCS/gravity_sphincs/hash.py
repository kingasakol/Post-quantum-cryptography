from gravity_sphincs.common import HASH_SIZE
from primitives.haraka import haraka256_256, haraka512_256, haraka256_256_chain
import hashlib


class Hash:
    def __init__(self, h=None):
        if h:
            self.h = h
        else:
            self.h = [None for _ in range(HASH_SIZE)]

    def __eq__(self, other):
        if isinstance(other, Hash):
            for i in range(HASH_SIZE):
                if self.h[i] != other.h[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return self.to_bytes().hex()

    def to_bytes(self):
        b = [(x.to_bytes(1, "big")) if x is not None else bytes(1) for x in self.h]
        arr = b''
        for x in b:
            arr += x
        return arr


class Address:
    def __init__(self, index, layer):
        self.index = index
        self.layer = layer


def hashcpy(a: Hash, b: Hash):
    a.h = b.h.copy()


def hashzero(a):
    a.h = [0 for _ in range(16)]


def hashswap(a: Hash, b: Hash):
    tmp = a.h
    a.h = b.h
    b.h = tmp


def hash_N_to_N(src):
    return Hash(haraka256_256(src.h))


def hash_N_to_N_chain(src: Hash, chinelen: int) -> Hash:
    return Hash(haraka256_256_chain(src.h, chinelen))


# takes two Hashes and makes haraka on them
def hash_2N_to_N(src1: Hash, src2: Hash) -> Hash:
    return Hash(haraka512_256(src1.h + src2.h))


def hash_to_N(src: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(src)
    return h.digest()


def hash_compress_pairs(buf: [Hash], dst_id: int, src_id: int, count: int):
    for i in range(count):
        buf[dst_id + i] = hash_2N_to_N(buf[src_id + i * 2], buf[src_id + i * 2 + 1])


def hash_compress_all(src):
    print("hash_compress_all WARNING: verify if ok")
    return [hash_to_N(s) for s in src]


# this implementation allows to hash only selected num from dst and have bigger buf than result
def hash_parallel(dst: [Hash], src: [Hash], count: int):
    for i in range(count):
        dst[i] = hash_N_to_N(src[i])


def hash_parallel_chains(src: [Hash], chinelen: int) -> [Hash]:
    return [hash_N_to_N_chain(s, chinelen) for s in src]
