from finished.hash import Hash, Address, hashcpy, hash_2N_to_N
from finished.wots import WotsSign, WotsSK, LwotsPK, wots_gensk, lwots_genpk
from shaky.common import MERKLE_h, MERKLE_hhh, HASH_SIZE, GRAVITY_OK
from utils.hash_utlis import hash_to_bytes


class MerklePK:
    def __init__(self):
        self.k = Hash()


class MerkleSign:
    def __int__(self):
        self.wots = WotsSign()
        self.auth = [Hash() for _ in range(MERKLE_h)]


def merkle_base_address(address: Address, base_address: Address) -> int:
    index = address.index & (MERKLE_hhh - 1)
    if base_address is not None:
        base_address.layer = address.layer
        base_address.index = address.index - index

    return index


# todo don't think that return is needed
# TESTED
def merkle_genpk(key: Hash, address: Address, pk: MerklePK) -> int:
    index = address.index & (MERKLE_hhh - 1)
    base_address = Address(address.index - index, address.layer)
    wsk = WotsSK()
    wpk = LwotsPK()
    buf = [None for _ in range(2 * (1 << MERKLE_h) * HASH_SIZE)]

    # leaves
    for j in range(MERKLE_hhh):
        wots_gensk(key, base_address, wsk)
        lwots_genpk(wsk, wpk)
        buf[j] = Hash(wpk.k.h.copy())
        base_address.index += 1

    merkle_compress_all(buf, MERKLE_h, pk.k)

    return GRAVITY_OK


# todo operates on buf in c-like pointer style
def merkle_gen_auth(buf: [Hash], height: int, auth: [Hash], index: int, root: Hash):
    n = 1 << height
    # inlining those below:
    src_id = n
    dst_id = 0
    for l in range(height):
        sibling = index ^ 1
        auth[l] = Hash(buf[dst_id + sibling].h.copy())
        index >>= 1
        src_id, dst_id = dst_id, src_id
        n >>= 1
        hash_compress_pairs_one_list(buf, dst_id, src_id, n)
    # Public key
    if root is not None:
        root.h = buf[0].h.copy()


# util performs  hash_compress_pairs but uses "continuous memory" and "pointers"
def hash_compress_pairs_one_list(src: [Hash], id_1: int, id_2: int, n: int):
    for i in range(n):
        src[id_1 + i] = hash_2N_to_N(src[id_2 + 2 * i], src[id_2 + 2 * i + 1])


# todo operates on buf in c-like pointer style
# TESTED BY TRANSITION
def merkle_compress_all(buf: [Hash], height: int, root: Hash):
    n = 1 << height
    src_id = 0
    dst_id = 0
    for l in range(height):
        src_id, dst_id = dst_id, src_id
        n >>= 1
        hash_compress_pairs_one_list(buf, dst_id, src_id, n)

    root.h = buf[dst_id].h.copy()

def merkle_genpk_test():
    k = Hash([i for i in range(32)])
    a = Address(1, 2)
    pk = MerklePK()
    merkle_genpk(k, a, pk)
    expected = "1603e9132467982229c6375d206f5631e8dca70c490bbed6002cdf1958c8e3c3"
    if hash_to_bytes(pk.k).hex() != expected:
        raise Exception("Test failed")

if __name__ == "__main__":
    merkle_genpk_test()
    print("ok")
