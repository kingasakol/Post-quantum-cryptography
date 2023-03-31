# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                  TODO                                       #
#                                ADD TESTS                                    #
#                                  TODO                                       #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
from finished.hash import Hash, Address, hash_compress_pairs, hash_2N_to_N
from shaky.common import GRAVITY_ccc, GRAVITY_d, GRAVITY_c, MERKLE_hhh, GRAVITY_OK, MERKLE_h, GRAVITY_ERR_VERIF, \
    HASH_SIZE, WOTS_ell
from shaky.merkle import MerklePK, merkle_genpk, merkle_sign, merkle_extract, merkle_compress_auth, MerkleSign
from shaky.pors import pors_randsubset, PorsSubset, PorsSK, pors_gensk, PorstPK, octoporst_sign, octoporst_extract, \
    octoporst_loadsign
from utils.hash_utlis import list_of_hashes_to_bytes, hashes_from_bytes


class GravitySK:
    def __init__(self, seed: Hash, cache=None):
        self.seed = seed
        self.salt = Hash()
        if cache:
            self.cache = cache
        else:
            self.cache = [Hash() for _ in range(2 * GRAVITY_ccc - 1)]


class GravitySign:
    def __init__(self):
        self.rand = Hash()
        self.op_sign = Hash()
        self.merkle = [MerkleSign() for _ in range(GRAVITY_d)]
        self.auth = [Hash() for _ in range(GRAVITY_c)]

    # todo untested
    def __eq__(self, other):
        if isinstance(other, GravitySign):
            if self.rand != other.rand:
                return False
            if self.op_sign != other.op_sign:
                return False
            for i in range(GRAVITY_d):
                if self.merkle[i] != other.merkle[i]:
                    return False
            for i in range(GRAVITY_c):
                if self.auth[i] != other.auth[i]:
                    return False
        return False


class GravityPK:
    def __init__(self):
        self.k = Hash()


# TESTED
def gravity_gensk(sk: GravitySK) -> int:
    n = GRAVITY_ccc
    dst_id = 0
    mpk = MerklePK()
    address = Address(None, 0)
    for i in range(n):
        print(f"[INFO] Generating Secret key {i}/{n}")
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


# TESTED
# TODO returns 1
def gravity_genpk(sk: GravitySK, pk: GravityPK) -> int:
    pk.k.h = sk.cache[2 * GRAVITY_ccc - 2].h.copy()
    return GRAVITY_OK


# todo returns 1 untested
def gravity_sign(sk: GravitySK, sign: GravitySign, msg: Hash) -> int:
    n = GRAVITY_ccc
    address = Address(None, GRAVITY_d)
    subset = PorsSubset()
    psk = PorsSK()
    ppk = PorstPK()
    mpk = MerklePK()

    sign.rand = hash_2N_to_N(sk.salt, msg)
    pors_randsubset(sign.rand, msg, address.index, subset)
    pors_gensk(sk.seed, address, psk)
    octoporst_sign(psk, sign.op_sign, ppk, subset)
    h = Hash(ppk.k.h.coppy())
    for layer in range(GRAVITY_d):
        address.layer -= 1
        merkle_sign(sk.seed, address, sign.merkle[layer], h, mpk)
        h.h = mpk.k.h
        address >>= MERKLE_h

    offset = 0
    for i in range(GRAVITY_c):
        sibling = address.index & 1
        sign.auth[i] = sk.cache[offset + sibling]
        address.index >>= 1
        offset += n
        n >>= 1

    return GRAVITY_OK


# todo returns 1 untested
def gravity_verify(pk: GravityPK, sign: GravitySign, msg: Hash) -> int:
    address = Address(None, GRAVITY_d)
    subset = PorsSubset()
    ppk = PorstPK()
    mpk = MerklePK()

    pors_randsubset(sign.rand, msg, address.index, subset)
    res = octoporst_extract(ppk, sign.op_sign, subset)
    if res != GRAVITY_OK:
        return res

    h = Hash(ppk.k.h.coppy())

    for layer in range(GRAVITY_d):
        address -= 1
        merkle_extract(mpk, address, sign.merkle[layer], h)
        h.h = mpk.k.h.copy()
        address.index >>= MERKLE_h

    if GRAVITY_c > 0:
        merkle_compress_auth(h, address.index, sign.auth, GRAVITY_c)

    if h != pk.k:
        return GRAVITY_ERR_VERIF

    return GRAVITY_OK


# TODO int, untested
# TODO maybe accept bytearray as _sign?
def gravity_loadsign(sign: GravitySign, _sign: [int], _len: int) -> int:
    base_len = HASH_SIZE * (MERKLE_h + 1 + WOTS_ell * GRAVITY_d) + GRAVITY_c
    if GRAVITY_c > 0:
        base_len += HASH_SIZE

    if _len < base_len:
        return GRAVITY_ERR_VERIF
    _len -= base_len
    sign.rand = Hash(_sign[:HASH_SIZE])
    _sign = _sign[HASH_SIZE:]

    if octoporst_loadsign(sign.op_sign, _sign, _len) != GRAVITY_OK:
        return GRAVITY_ERR_VERIF
    _sign = _sign[_len:]

    for i in range(GRAVITY_d):
        # todo maybe add sizeof method...
        sign.merkle[i] = _sign[(HASH_SIZE * (WOTS_ell + MERKLE_h)) * i: (HASH_SIZE * (WOTS_ell + MERKLE_h)) * (i + 1)]

    if GRAVITY_c > 0:
        _sign = _sign[(HASH_SIZE * (WOTS_ell + MERKLE_h)) * GRAVITY_d:]
        sign.auth = _sign[GRAVITY_c * HASH_SIZE:]
    return GRAVITY_OK


# TEST UTILS ---------------------------------------------


def gravity_gensk_test():
    k = GravitySK(Hash([i for i in range(32)]))
    gravity_gensk(k)
    expected = get_expected_SK().cache
    if k.cache != expected:
        print("Actual: " + list_of_hashes_to_bytes(k.cache).hex())
        print("Expected: " + list_of_hashes_to_bytes(expected).hex())
        raise Exception("Test failed")


def gravity_genpk_test():
    sk = get_expected_SK()
    pk = GravityPK()
    gravity_genpk(sk, pk)
    expected = "417d807ebfb44d62d88d4681854f8741effd7168b6230ea4264a54c0832c797b" if GRAVITY_c == 3 else "a73e2eb8e10194f424bdafd86ad6c89cf90b9849fe19aeca38c9668512eac6a2"
    if pk.k.to_bytes().hex() != expected:
        raise Exception("Test failed")


def get_expected_SK() -> GravitySK:
    if GRAVITY_c == 1:
        cache = bytes.fromhex(
            "20b97e26ac1c97d2cba431e1c75a6909b743bb7cf260dc076929e2a842ffb90543eb2967250331694e7aea03dc339f3b46809382f0c659951f6dae0b557da014a73e2eb8e10194f424bdafd86ad6c89cf90b9849fe19aeca38c9668512eac6a2")
        return GravitySK(Hash([i for i in range(32)]), hashes_from_bytes(cache))
    elif GRAVITY_c == 3:
        cache = bytes.fromhex(
            "20b97e26ac1c97d2cba431e1c75a6909b743bb7cf260dc076929e2a842ffb90543eb2967250331694e7aea03dc339f3b46809382f0c659951f6dae0b557da014ab88fcf77a62090031a5d4c50c79c6da512a35a53bf968d45611edd644df2266c3b9833b1b2498061598598322063cbdb9a5268ffdaac1703e695f0f82dd72c2c7349f3173e5b57335106420319e0e1cc24c9b51e646363513e104e5781489f75f6efe62cb64f40adb01244579db1de28df498e09ed6afb0e588748d7c2cf3f271bf4fea6e9e72ae088d68fece5e82b22ae0b07a3850c284c6416094ca72b5856241448c9fa36a747f2ac02c78a5256e194596dc25997c31b812d256adfd99caa73e2eb8e10194f424bdafd86ad6c89cf90b9849fe19aeca38c9668512eac6a2f46676ac683839687a9fd6669df9bd5116de7096ac2b25b1ff8e1a5d4b75c65dc1bf3bd78915bf4aa561ea110554d2248b1b3645efc8fb57a721b41e753eef6d00e3932fa5e9996cfaa26d2bbfffc4d902c6941c9e637de452a8318928022a75d42a40813a0828da07357718a69887620cd831d565dc64799f71195b37367c8f8cbf7c5004f7bc9b2b9f40bc016674d468fe931c71a7e21ec3d893f4d48323fa417d807ebfb44d62d88d4681854f8741effd7168b6230ea4264a54c0832c797b")
        return GravitySK(Hash([i for i in range(32)]), hashes_from_bytes(cache))


def gravity_sign_test():
    sk = get_expected_SK()
    sign = GravitySign()
    gravity_sign(sk, sign, Hash([i*2 for i in HASH_SIZE]))
    print(sign.op_sign)


if __name__ == "__main__":
    if GRAVITY_c != 1 and GRAVITY_c != 3:
        raise Exception("To run tests set GRAVITY_c to 1 or 3 fot this test")
    gravity_genpk_test()
    gravity_gensk_test()
    gravity_sign_test()
    print("ok")
