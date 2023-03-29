# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                  TODO                                       #
#                                ADD TESTS                                    #
#                                  TODO                                       #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
from finished.hash import Hash, Address, hash_compress_pairs
from shaky.common import GRAVITY_ccc, GRAVITY_d, GRAVITY_c, MERKLE_hhh, GRAVITY_OK
from shaky.merkle import MerklePK, merkle_genpk
from utils.hash_utlis import hash_to_bytes, list_of_hashes_to_bytes


class GravitySk:
    def __init__(self, seed: Hash):
        self.seed = seed
        self.salt = Hash()
        self.cache = [Hash() for _ in range(2 * GRAVITY_ccc - 1)]


# TESTED
def gravity_gensk(sk: GravitySk) -> int:
    n = GRAVITY_ccc
    dst_id = 0
    mpk = MerklePK()
    address = Address(None, 0)
    for i in range(n):
        print(f"[INFO] Generating Secret key {i+1}/{n}")
        address.index = i * MERKLE_hhh
        res = merkle_genpk(sk.seed, address, mpk)
        if res != GRAVITY_OK:
            return res
        sk.cache[i].h = mpk.k.h.copy()
    for i in range(GRAVITY_c):
        src_id = dst_id
        dst_id += n
        n >>= 1
        hash_compress_pairs(sk.cache, dst_id, src_id, n)
    print("[INFO] Gravity secret key generated!")
    return GRAVITY_OK


class GravityPk:
    def __init__(self, k):
        self.k = Hash()


class GravitySign:
    def __init__(self):
        self.rand = None
        self.op_sign = None
        self.merkle_sign = [None for _ in range(GRAVITY_d)]
        self.auth = [None for _ in range(GRAVITY_c)]


def gravity_gensk_test():
    if GRAVITY_c != 1:
        raise Exception("To run this test set GRAVITY_c to 1 - test will be faster")
    k = GravitySk(Hash([i for i in range(32)]))
    gravity_gensk(k)
    expected = "20b97e26ac1c97d2cba431e1c75a6909b743bb7cf260dc076929e2a842ffb90543eb2967250331694e7aea03dc339f3b46809382f0c659951f6dae0b557da014a73e2eb8e10194f424bdafd86ad6c89cf90b9849fe19aeca38c9668512eac6a2"
    if list_of_hashes_to_bytes(k.cache).hex() != expected:
        print(list_of_hashes_to_bytes(k.cache).hex())
        raise Exception("Test failed")


if __name__ == "__main__":
    gravity_gensk_test()
    print("ok")
