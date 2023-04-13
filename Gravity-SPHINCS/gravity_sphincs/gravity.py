from gravity_sphincs.hash import Hash, Address, hash_compress_pairs, hash_2N_to_N
from gravity_sphincs.common import GRAVITY_ccc, GRAVITY_d, GRAVITY_c, MERKLE_hhh, GRAVITY_OK, MERKLE_h, GRAVITY_ERR_VERIF, \
    HASH_SIZE
from gravity_sphincs.merkle import MerklePK, merkle_genpk, merkle_sign, merkle_extract, merkle_compress_auth, MerkleSign, \
    merkle_sign_list_to_bytes
from gravity_sphincs.pors import pors_randsubset, PorsSubset, PorsSK, pors_gensk, PorstPK, octoporst_sign, octoporst_extract, \
    OctoporstSign
from utils.bytes_utils import bytes_to_int_list
from utils.hash_utlis import list_of_hashes_to_bytes, hashes_from_bytes


class GravitySK:
    def __init__(self, seed: Hash, cache=None, salt=None):
        self.seed = seed
        self.salt = Hash()
        self.cache = [Hash() for _ in range(2 * GRAVITY_ccc - 1)]
        if cache:
            self.cache = cache
        if salt:
            self.salt = salt

    def save(self) -> bytes:
        return self.seed.to_bytes() + self.salt.to_bytes() + list_of_hashes_to_bytes(self.cache)

    @staticmethod
    def load(src: bytes) -> 'GravitySK':
        seed = Hash(bytes_to_int_list(src[:HASH_SIZE]))
        src = src[HASH_SIZE:]
        salt = Hash(bytes_to_int_list(src[:HASH_SIZE]))
        src = src[HASH_SIZE:]
        cache = hashes_from_bytes(src)
        return GravitySK(seed, cache, salt)

    def __repr__(self):
        return f"GRAVITY SK: {{seed: {self.seed}, salt: {self.salt}, cache:{self.cache}}}"


class GravitySign:
    def __init__(self):
        self.rand = Hash()
        self.op_sign = OctoporstSign()
        self.merkle = [MerkleSign() for _ in range(GRAVITY_d)]
        self.auth = [Hash() for _ in range(GRAVITY_c)]

    # TESTED
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
            return True
        return False

    def __repr__(self):
        return f'GRAVITY SIGN: {{rand: {self.rand}, op_sign: {self.op_sign}, merkle: {self.merkle}, auth: {self.auth}}}'

    def save(self) -> bytes:
        return self.rand.to_bytes() + merkle_sign_list_to_bytes(self.merkle) + list_of_hashes_to_bytes(
            self.auth) + self.op_sign.save()

    # TESTED
    @staticmethod
    def load(sign: bytes) -> 'GravitySign':
        sign = bytes_to_int_list(sign)
        res = GravitySign()
        res.rand = Hash(sign[:HASH_SIZE])
        sign = sign[HASH_SIZE:]
        for i in range(GRAVITY_d):
            res.merkle[i] = MerkleSign.load(sign[MerkleSign.size() * i: MerkleSign.size() * (i + 1)])
        sign = sign[MerkleSign.size() * GRAVITY_d:]
        for i in range(GRAVITY_c):
            res.auth[i] = Hash(sign[HASH_SIZE * i: HASH_SIZE * (i + 1)])
        sign = sign[HASH_SIZE * GRAVITY_c:]
        res.op_sign = OctoporstSign.load(sign)
        return res


class GravityPK:
    def __init__(self, k=None):
        if k:
            self.k = k
        else:
            self.k = Hash()


# TESTED
def gravity_gensk(sk: GravitySK):
    n = GRAVITY_ccc
    dst_id = 0
    mpk = MerklePK()
    address = Address(None, 0)
    for i in range(n):
        print(f"[INFO] Generating Secret key {i}/{n}")
        address.index = i * MERKLE_hhh
        merkle_genpk(sk.seed, address, mpk)
        sk.cache[i].h = mpk.k.h.copy()
    for i in range(GRAVITY_c):
        src_id = dst_id
        dst_id += n
        n >>= 1
        hash_compress_pairs(sk.cache, dst_id, src_id, n)
    print("[INFO] Gravity secret key generated!")


# TESTED
def gravity_genpk(sk: GravitySK, pk: GravityPK) -> int:
    pk.k.h = sk.cache[2 * GRAVITY_ccc - 2].h.copy()


# TESTED
def gravity_sign(sk: GravitySK, sign: GravitySign, msg: Hash):
    n = GRAVITY_ccc
    address = Address(None, GRAVITY_d)
    subset = PorsSubset()
    psk = PorsSK()
    ppk = PorstPK()
    mpk = MerklePK()

    sign.rand = hash_2N_to_N(sk.salt, msg)
    pors_randsubset(sign.rand, msg, address, subset)
    pors_gensk(sk.seed, address, psk)
    print(f"[INFO] Starting Octoporst sign")
    octoporst_sign(psk, sign.op_sign, ppk, subset)
    print(f"[INFO] Octoporst sign completed")
    h = Hash(ppk.k.h.copy())
    for layer in range(GRAVITY_d):
        print(f"[INFO] Starting merkle sign {layer + 1} / {GRAVITY_d}")
        address.layer -= 1
        merkle_sign(sk.seed, address, sign.merkle[layer], h, mpk)
        h.h = mpk.k.h.copy()
        address.index >>= MERKLE_h
    print(f"[INFO] Merkle sign completed for all layers")
    offset = 0
    for i in range(GRAVITY_c):
        sibling = address.index ^ 1
        sign.auth[i] = sk.cache[offset + sibling]
        address.index >>= 1
        offset += n
        n >>= 1


# TESTED
def gravity_verify(pk: GravityPK, sign: GravitySign, msg: Hash) -> bool:
    address = Address(None, GRAVITY_d)
    subset = PorsSubset()
    ppk = PorstPK()
    mpk = MerklePK()

    pors_randsubset(sign.rand, msg, address, subset)
    res = octoporst_extract(ppk, sign.op_sign, subset)
    if not res:
        return False

    h = Hash(ppk.k.copy())
    for layer in range(GRAVITY_d):
        address.layer -= 1
        merkle_extract(mpk, address, sign.merkle[layer], h)
        h.h = mpk.k.h.copy()
        address.index >>= MERKLE_h

    if GRAVITY_c > 0:
        merkle_compress_auth(h, address.index, sign.auth, GRAVITY_c)

    if h != pk.k:
        return False

    return True
