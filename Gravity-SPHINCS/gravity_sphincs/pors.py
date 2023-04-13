from primitives.aes import aesctr256_zeroiv
from gravity_sphincs.hash import Hash, Address, hash_parallel, hash_2N_to_N
from gravity_sphincs.common import PORS_t, PORS_k, HASH_SIZE, PORS_tau, GRAVITY_OK, GRAVITY_mask
from gravity_sphincs.merkle import merkle_alloc_buf, merkle_compress_all, merkle_gen_octopus, merkle_compress_octopus
from utils.hash_utlis import list_of_hashes_to_bytes
from utils.key_utils import gensk

BYTES_PER_INDEX = 4
STREAMLEN = 8 * PORS_k + HASH_SIZE


class PorsSubset:
    def __init__(self):
        self.s = [None for _ in range(PORS_k)]  # [int]


class PorsSK:
    def __init__(self):
        self.k = [Hash() for _ in range(PORS_t)]

    def __repr__(self):
        print(f'PORS SK: {{k: {self.k}}}')


class PorsPK:
    def __init__(self):
        self.k = [None for _ in range(PORS_t)]


class PorsKeyPair():
    def __init__(self):
        self.pors_sk = PorsSK()
        self.pors_pk = PorsPK()


class PorsSign:
    def __init__(self):
        self.s = [Hash() for _ in range(PORS_k)]

    # TESTED
    def __eq__(self, other):
        if isinstance(other, PorsSign):
            for i in range(PORS_k):
                if self.s[i] != other.s[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return f'PORS SIGN: {{s:{self.s}}}'

    @staticmethod
    def size():
        return PORS_k * HASH_SIZE


class PorstPK:
    def __init__(self):
        self.k = Hash()


class PorstKeypair:
    def __init__(self):
        self.sk = PorsSK()
        self.pl = PorstPK()


# PORST with authentication octopus
class OctoporstSign:
    s = PorsSign()
    octopus = [Hash() for _ in range(PORS_k * PORS_tau)]
    octolen = None

    # TESTED
    def __eq__(self, other):
        if isinstance(other, OctoporstSign):
            if self.octolen != other.octolen:
                return False
            for i in range(self.octolen):
                if self.octopus[i] != other.octopus[i]:
                    return False
            return self.s == other.s
        return False

    def __repr__(self):
        return f'OCTOPORST SIGN: {{s: {self.s}, octopus: {self.octopus}, octolen: {self.octolen}}}'

    @staticmethod
    def size():
        return PorsSign.size() + HASH_SIZE * PORS_k * PORS_tau

    # length can be used if one wants to pass source with zeros at the end
    # TESTED
    @staticmethod
    def load(sign: [int], length=None) -> 'OctoporstSign':
        if not length:
            length = len(sign)
        result = OctoporstSign()
        length -= PorsSign.size()
        length /= HASH_SIZE
        for i in range(PORS_k):
            result.s.s[i] = Hash(sign[i * HASH_SIZE: (i + 1) * HASH_SIZE])
        sign = sign[PorsSign.size():]
        for i in range(int(length)):
            result.octopus[i] = Hash(sign[i * HASH_SIZE: (i + 1) * HASH_SIZE])
        result.octolen = int(length)
        return result

    def save(self):
        return  list_of_hashes_to_bytes(self.s.s) + list_of_hashes_to_bytes(self.octopus[:self.octolen])


# TESTED
def pors_gensk(key: Hash, address: Address, sk: PorsSK):
    gensk(key, address, sk, PORS_t)


# TESTED BY GRAVITY SIGN
def pors_sign(sk: PorsSK, sign: PorsSign, subset: PorsSubset):
    for i in range(PORS_k):
        index = subset.s[i]
        sign.s[i].h = sk.k[index].h.copy()


def porst_genpk(sk: PorsSK, pk: PorstPK):
    buf = merkle_alloc_buf(PORS_tau)
    hash_parallel(buf, sk.k, PORS_t)
    merkle_compress_all(buf, PORS_tau, pk.k)


def sort_subset(subset: PorsSubset):
    subset.s.sort()


# TESTED BY GRAVITY SIGN
def octoporst_sign(sk: PorsSK, sign: OctoporstSign, pk: PorstPK, subset: PorsSubset) -> int:
    sort_subset(subset)
    pors_sign(sk, sign.s, subset)
    buf = merkle_alloc_buf(PORS_tau)
    hash_parallel(buf, sk.k, PORS_t)
    sign.octolen = merkle_gen_octopus(buf, PORS_tau, sign.octopus, pk.k, subset.s, PORS_k)
    return GRAVITY_OK


# TESTED BY GRAVITY VERIFY
def octoporst_extract(pk: PorstPK, sign: OctoporstSign, subset: PorsSubset) -> bool:
    tmp = [Hash() for _ in range(PORS_k)]
    sort_subset(subset)
    hash_parallel(tmp, sign.s.s, PORS_k)
    res = merkle_compress_octopus(tmp, PORS_tau, sign.octopus, sign.octolen, subset.s, PORS_k)
    pk.k = tmp[0].h.copy()
    return res


# TESTED
def pors_randsubset(rand: Hash, msg: Hash, address: Address, subset: PorsSubset):
    seed = hash_2N_to_N(rand, msg)
    rand_stream = aesctr256_zeroiv(seed.to_bytes(), STREAMLEN)
    addr = 0
    count = 0
    offset = 0
    for i in range(HASH_SIZE):
        byte = rand_stream[i]
        addr = (addr << 8) | byte
        addr &= GRAVITY_mask
    address.index = addr
    while count < PORS_k:
        index = int.from_bytes(rand_stream[HASH_SIZE + offset: HASH_SIZE + offset + 32][:4], byteorder='big') % PORS_t
        offset += BYTES_PER_INDEX
        duplicate = False
        for i in range(count):
            if subset.s[i] == index:
                duplicate = True
                break
        if not duplicate:
            subset.s[count] = index
            count += 1
