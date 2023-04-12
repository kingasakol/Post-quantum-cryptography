from gravity_sphincs.hash import Hash
from gravity_sphincs.common import HASH_SIZE
from utils.bytes_utils import bytes_to_int_list


def list_of_hashes_to_bytes(h: [Hash]) -> bytes:
    arr = b''
    for x in h:
        arr += x.to_bytes()
    return arr


def hashes_from_bytes(b: bytes) -> [Hash]:
    ints = bytes_to_int_list(b)
    return [Hash(ints[i * HASH_SIZE: (i + 1) * HASH_SIZE]) for i in range(len(ints) // HASH_SIZE)]


if __name__ == "__main__":
    a = Hash()
    a.h = [i for i in range(32)]
    b = Hash()
    b.h = [3 * i for i in range(32)]
    print(list_of_hashes_to_bytes([a, b]).hex())
