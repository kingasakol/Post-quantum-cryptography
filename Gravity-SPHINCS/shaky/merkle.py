from finished.hash import Hash, Address, hashcpy
from finished.wots import WotsSign, WotsSK, LwotsPK, wots_gensk, lwots_genpk
from shaky.common import MERKLE_h, MERKLE_hhh, HASH_SIZE, GRAVITY_OK


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


def merkle_genpk(key: Hash, address: Address, pk: MerklePK) -> int:
    index = address.index & (MERKLE_hhh - 1)
    base_address = Address(address.layer,  address.index - index)
    wsk = WotsSK()
    wpk = LwotsPK()
    buf = [None for _ in range(2 * (1 << MERKLE_h) * HASH_SIZE)]

    # leaves
    for j in range(MERKLE_hhh):
        wots_gensk(key, base_address, wsk)
        lwots_genpk(wsk, wpk)
        buf[j] = Hash(wpk.k.h.copy())
        base_address.index += 1


    # todo merkle_compress_all (buf, MERKLE_h, &pk->k);
    raise Exception("TODO")

    return GRAVITY_OK
