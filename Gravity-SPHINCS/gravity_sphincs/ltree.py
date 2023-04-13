from gravity_sphincs.hash import *


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
