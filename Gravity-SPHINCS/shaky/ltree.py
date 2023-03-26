from common import WOTS_ell
from finished.hash import *
from utils.hash_utlis import hash_to_bytes


def ltree(buf: [Hash]) -> Hash:
    while len(buf) > 1:
        new_buf = []
        for i in range(0, len(buf), 2):
            if i == len(buf) - 1:
                new_buf.append(buf[-1])
                break
            new_buf.append(hash_2N_to_N(buf[i], buf[i + 1]))
        buf = new_buf
    return buf[0]


def test():
    h = [Hash([i + 1 for _ in range(32)]) for i in range(5)]
    res = (hash_to_bytes(ltree(h)).hex())
    expected = "3ee3c6ebc10948763f4c69f9d0a744c1961abdbde86a900e2a4301d30226314f"
    if res != expected:
        raise Exception("Test failed")


if __name__ == "__main__":
    test()
    print("ok")
