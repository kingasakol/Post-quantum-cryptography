from finished.hash import Hash
from utils.bytes_utils import int_list_to_bytes


def hash_to_bytes(h: Hash) -> bytes:
    return int_list_to_bytes(h.h)


def list_of_hashes_to_bytes(h: [Hash]) -> bytes:
    arr = b''
    for x in h:
        arr += hash_to_bytes(x)
    return arr


if __name__ == "__main__":
    a = Hash()
    a.h = [i for i in range(32)]
    b = Hash()
    b.h = [3*i for i in range(32)]
    print(list_of_hashes_to_bytes([a,b]).hex())
