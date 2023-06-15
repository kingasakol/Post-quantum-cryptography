import numpy as np
from LEDAkem.circulant_matrix_helper import circulant_matrix_mod, circulant_transpose
from LEDAkem.key_generation import key_generation
from LEDAkem.ourGF2.gf2x_add import gf2x_add
from LEDAkem.prng import binary_block_generate
from LEDAkem.trng import trng
from hashlib import sha3_256


def encrypt_niederreiter(M, n0, p, t, sha3, TRNG_byte_len, polynomial):
    seed = trng(TRNG_byte_len)
    e = binary_block_generate(seed, n0 * p, t)
    e = np.reshape(e, (n0, p))
    s = sha3(e).digest()
    helper_arr = np.zeros(p, dtype='uint8')
    for i in range(n0 - 1):
        helper_arr = gf2x_add(helper_arr, circulant_matrix_mod(circulant_transpose(e[i,:], p), M[i], polynomial))

    c = gf2x_add(helper_arr, circulant_transpose(e[-1, :], p))

    return s, c


if __name__ == "__main__":
    pol = np.array([1] + (15013 - 1) * [0] + [1], dtype="uint8")
    seed = trng(24)
    M = key_generation(seed, 2, 15013, 9, np.array([5, 4]), pol)

    s, c = encrypt_niederreiter(M, 2, 15013, 143, sha3_256, 24)

    print(s.hex())
    print(c)