from gravity_sphincs.hash import hash_N_to_N_chain, Hash, Address, hash_parallel_chains
from gravity_sphincs.common import WOTS_ell, HASH_SIZE, WOTS_ell1, WOTS_w
from gravity_sphincs.ltree import ltree
from utils.hash_utlis import list_of_hashes_to_bytes
from utils.key_utils import gensk


class WotsSK:
    def __init__(self):
        self.k = [Hash() for _ in range(WOTS_ell)]


class WotsPK:
    def __init__(self):
        self.k = [Hash() for _ in range(WOTS_ell)]


class LwotsPK:
    def __init__(self):
        self.k = Hash()


class WotsSign:
    def __init__(self, src=None):
        if src:
            self.s = [Hash(src[i * HASH_SIZE: (i + 1) * HASH_SIZE]) for i in range(WOTS_ell)]
        else:
            self.s = [Hash() for _ in range(WOTS_ell)]

    def __eq__(self, other):
        if isinstance(other, WotsSign):
            for i in range(WOTS_ell):
                if self.s[i] != other.s[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return f'WOTS SIGN: {{ s: {self.s}}}'

    @staticmethod
    def size():
        return HASH_SIZE * WOTS_ell


# HAS TRANSITIVE TEST
def wots_chain(src: Hash, count: int) -> Hash:
    return hash_N_to_N_chain(src, count)


#  TESTED
def wots_gensk(key: Hash, address: Address, sk: WotsSK):
    gensk(key, address, sk, WOTS_ell)


# TESTED
def wots_sign(sk: WotsSK, sign: WotsSign, msg: Hash):
    checksum = 0

    for i in range(0, WOTS_ell1, 2):
        v = msg.h[i // 2]
        a = (v >> 4) & 15
        b = v & 15
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)

        sign.s[i] = wots_chain(sk.k[i], a)
        sign.s[i + 1] = wots_chain(sk.k[i + 1], b)

    # Checksum values
    for i in range(WOTS_ell1, WOTS_ell):
        sign.s[i] = wots_chain(sk.k[i], checksum & 15)
        checksum >>= 4


# WOTS with L-tree and without masks */
# TESTED
def lwots_ltree(pk: WotsPK, root: LwotsPK):
    root.k = ltree(pk.k[:2 * WOTS_ell])


# TESTED
def lwots_genpk(sk: WotsSK, pk: LwotsPK):
    tmp = WotsPK()

    tmp.k = hash_parallel_chains(sk.k, WOTS_w - 1)
    lwots_ltree(tmp, pk)


# TESTED
def lwots_extract(pk: LwotsPK, sign: WotsSign, msg: Hash):
    tmp = WotsPK()

    checksum = 0
    for i in range(0, WOTS_ell1, 2):
        v = msg.h[i // 2]
        a = (v >> 4) & 15
        b = v & 15
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)
        tmp.k[i] = wots_chain(sign.s[i], WOTS_w - 1 - a)
        tmp.k[i + 1] = wots_chain(sign.s[i + 1], WOTS_w - 1 - b)

    # Checksum values
    for i in range(WOTS_ell1, WOTS_ell):
        tmp.k[i] = wots_chain(sign.s[i], WOTS_w - 1 - (checksum & 15))
        checksum >>= 4

    lwots_ltree(tmp, pk)
