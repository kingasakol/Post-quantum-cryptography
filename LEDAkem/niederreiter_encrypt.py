import numpy as np

from LEDAkem.circulant_matrix_helper import circulant_matrix_mod
from LEDAkem.key_generation import key_generation
from LEDAkem.ourGF2.generic_functions import padding, strip_zeros
from LEDAkem.ourGF2.gf2_add import gf2_add
from LEDAkem.ourGF2.gf2_div import gf2_div
from LEDAkem.prng import binary_block_generate
from LEDAkem.trng import trng
from hashlib import sha3_256


def encrypt_niederreiter(M, n0, p, t, sha3, TRNG_byte_len):

    seed = trng(TRNG_byte_len)
    e = binary_block_generate(seed, n0 * p, t)

    # e = np.reshape(e, (n0, p))
    #
    # s = sha3(e).digest()
    #
    # helper_arr = np.zeros(p, dtype='uint8')
    #
    # for i in range(n0 - 1):
    #     helper_arr = gf2x_add(helper_arr, circulant_matrix_mod(circulant_transpose(e[i,:], p), M[i]))
    #
    # c = gf2x_add(helper_arr, (e[-1, :], p))
    #
    # return s, c

    e = binary_block_generate(seed, n0*p, t) # LEDAKem uses AES-256 generator here

    e = np.reshape(e, (n0,p))

    Ks = sha3(e).digest()  # LEDAKem SHA-3 uses

    tmp = np.zeros(p, dtype='uint8')

    for i in range(n0 - 1):
        tmp = gf2_add(tmp, circmatprod_GF2x(circtranspose(e[i,:], p), M[i]))

    c = gf2_add(tmp, circtranspose(e[-1, :], p))

    return Ks, c


if __name__ == "__main__":
    pol = np.array([1] + (15013 - 1) * [0] + [1], dtype="uint8")
    seed = trng(24)
    M = key_generation(seed, 2, 15013, 9, np.array([5, 4]), pol)

    s, c = encrypt_niederreiter(M, 2, 15013, 143, sha3_256, 24)

    print(s.hex())
    print(c)


def circtranspose(a, p):
    at = np.copy(a)  # TODO copy ?
    at = padding(at, p)

    at[1:] = np.flip(at[1:], axis=0)

    return at


def circmatprod_GF2x(a, b):
    """given two numpy arrays 'a' and 'b' which elements corresponds to the elements of the first rows
           of two circulant matrices 'A' and 'B' returns an array whose elements corresponds to the elements of the first row
           of the circulant matrix obtained as the product of the two circulant matrices A and B in GF2[x]

    """
    a, b = strip_zeros(a), strip_zeros(b)

    fsize = len(a) + len(b) + 1

    fsize = 2 ** np.ceil(np.log2(fsize)).astype(int)  # use nearest power of two much faster

    fslice = slice(0, fsize)

    ta = np.fft.fft(a, fsize)
    tb = np.fft.fft(b, fsize)

    res = np.fft.ifft(ta * tb)[fslice].copy()

    k = np.mod(np.rint(np.real(res)).astype("uint64"), 2)

    out = gf2_div(k,  np.array([1] + (15013 - 1) * [0] + [1], dtype="uint8"))[1]

    # these operations are equal to do #np.mod(np.rint(np.real(np.fft.ifft(np.fft.fft(a) * np.fft.fft(b)))),2).astype("uint8")
    # but much faster

    return strip_zeros(out)