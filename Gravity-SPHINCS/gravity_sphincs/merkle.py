from gravity_sphincs.hash import Hash, Address, hash_2N_to_N
from gravity_sphincs.wots import WotsSign, WotsSK, LwotsPK, wots_gensk, lwots_genpk, wots_sign, lwots_extract
from gravity_sphincs.common import MERKLE_h, MERKLE_hhh, HASH_SIZE, GRAVITY_OK, WOTS_ell, GRAVITY_ERR_VERIF
from utils.hash_utlis import list_of_hashes_to_bytes


class MerklePK:
    def __init__(self):
        self.k = Hash()


class MerkleSign:
    def __init__(self, src=None):
        if src:
            self.wots = WotsSign(src)
            self.auth = [Hash(src[HASH_SIZE * (WOTS_ell + i): HASH_SIZE * (WOTS_ell + i + 1)]) for i in range(MERKLE_h)]
        else:
            self.wots = WotsSign()
            self.auth = [Hash() for _ in range(MERKLE_h)]

    def __eq__(self, other):
        if isinstance(other, MerkleSign):
            if self.wots != other.wots:
                return False
            for i in range(MERKLE_h):
                if self.auth[i] != other.auth[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return f'MERKLE SIGN: {{ wots: {self.wots}, auth: {self.auth}}}'

    def hex(self):
        return list_of_hashes_to_bytes(self.wots.s).hex() + list_of_hashes_to_bytes(self.auth).hex()

    def bytes(self):
        return list_of_hashes_to_bytes(self.wots.s) + list_of_hashes_to_bytes(self.auth)

    @staticmethod
    def size():
        return WotsSign.size() + HASH_SIZE * MERKLE_h

    @staticmethod
    def load(merkle: [int]) -> 'MerkleSign':
        res = MerkleSign()
        for i in range(WOTS_ell):
            res.wots.s[i] = Hash(merkle[HASH_SIZE * i: HASH_SIZE * (i + 1)])
        for i in range(MERKLE_h):
            res.auth[i] = Hash(merkle[WotsSign.size() + i * HASH_SIZE: WotsSign.size() + (i + 1) * HASH_SIZE])
        return res


# util - performs hash_compress_pairs but uses "continuous memory" and "pointers"
def hash_compress_pairs_one_list(src: [Hash], id_1: int, id_2: int, n: int):
    for i in range(n):
        src[id_1 + i] = hash_2N_to_N(src[id_2 + 2 * i], src[id_2 + 2 * i + 1])


def merkle_alloc_buf(n: int) -> [None]:
    return [None for _ in range(2 * (1 << n))]


def merkle_sign_list_to_bytes(signs: [MerkleSign]) -> bytes:
    res = b''
    for s in signs:
        res += s.bytes()
    return res


# TESTED
def merkle_genpk(key: Hash, address: Address, pk: MerklePK):
    index = address.index & (MERKLE_hhh - 1)
    base_address = Address(address.index - index, address.layer)
    wsk = WotsSK()
    wpk = LwotsPK()
    buf = merkle_alloc_buf(MERKLE_h)

    # leaves
    for j in range(MERKLE_hhh):
        wots_gensk(key, base_address, wsk)
        lwots_genpk(wsk, wpk)
        buf[j] = Hash(wpk.k.h.copy())
        base_address.index += 1

    merkle_compress_all(buf, MERKLE_h, pk.k)


# TESTED
def merkle_sign(key: Hash, address: Address, sign: MerkleSign, msg: Hash, pk: MerklePK) -> int:
    wsk = WotsSK()
    wpk = LwotsPK()
    index = address.index & (MERKLE_hhh - 1)
    base_address = Address(address.index - index, address.layer)
    buf = merkle_alloc_buf(MERKLE_h)

    for j in range(MERKLE_hhh):
        wots_gensk(key, base_address, wsk)
        lwots_genpk(wsk, wpk)
        buf[j] = Hash(wpk.k.h.copy())
        base_address.index += 1

        if j == index:
            wots_sign(wsk, sign.wots, msg)

    merkle_gen_auth(buf, MERKLE_h, sign.auth, index, None if pk is None else pk.k)
    return GRAVITY_OK


# TESTED
def merkle_extract(pk: MerklePK, address: Address, sign: MerkleSign, msg: Hash):
    wpk = LwotsPK()
    index = address.index & (MERKLE_hhh - 1)

    lwots_extract(wpk, sign.wots, msg)

    merkle_compress_auth(wpk.k, index, sign.auth, MERKLE_h)
    pk.k.h = wpk.k.h.copy()


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


# TESTED BY TRANSITION
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
        root.h = buf[dst_id].h.copy()


# TESTED BY TRANSITION
def merkle_compress_auth(node: Hash, index: int, auth: [Hash], height_diff: int) -> int:
    for l in range(height_diff):
        if index % 2 == 0:
            node.h = hash_2N_to_N(Hash(node.h.copy()), Hash(auth[l].h.copy())).h
        else:
            node.h = hash_2N_to_N(Hash(auth[l].h.copy()), Hash(node.h.copy())).h
        index >>= 1

    return index


# returns octolen as int is primitive
# TESTED BY GRAVITY SIGN
def merkle_gen_octopus(buf: [Hash], height: int, octopus: [Hash], root: Hash, indices: [int], count: int) -> int:
    n = 1 << height
    src_id = n
    dst_id = 0
    length = 0

    for l in range(height):
        i = 0
        j = 0
        # Copy auth octopus
        while i < count:
            index = indices[i]
            sibling = index ^ 1
            # Check redundancy with sibling
            if (i + 1) < count and indices[i + 1] == sibling:
                i += 1
            else:
                octopus[length].h = buf[dst_id + sibling].h.copy()
                length += 1
            indices[j] = indices[i] >> 1
            i += 1
            j += 1
        # Update count of non-redundant nodes
        count = j
        dst_id, src_id = src_id, dst_id
        n >>= 1
        # compute all hashes at current layer
        hash_compress_pairs_one_list(buf, dst_id, src_id, n)

    root.h = buf[dst_id].h.copy()
    return length


# TESTED BY GRAVITY_VERIFY
def merkle_compress_octopus(nodes: [Hash], height: int, octopus: [Hash], octolen: int, indices: [int],
                            count: int) -> bool:
    length = 0
    buf = [None, None]
    for l in range(height):
        i = 0
        j = 0
        while i < count:
            index = indices[i]
            if index % 2 == 0:
                buf[0] = Hash(nodes[i].h.copy())
                if (i + 1) < count and indices[i + 1] == index + 1:
                    i += 1
                    buf[1] = Hash(nodes[i].h.copy())
                else:
                    if length == octolen:
                        return False
                    buf[1] = Hash(octopus[length].h.copy())
                    length += 1
            else:
                if length == octolen:
                    return False
                buf[0] = Hash(octopus[length].h.copy())
                length += 1
                buf[1] = Hash(nodes[i].h.copy())
            nodes[j] = hash_2N_to_N(buf[0], buf[1])
            indices[j] = indices[i] >> 1
            i += 1
            j += 1
        count = j
    if length != octolen:
        return False
    return True
