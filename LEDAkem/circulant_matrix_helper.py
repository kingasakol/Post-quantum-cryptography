import numpy as np

from LEDAkem.ourGF2.gf2x_div import gf2x_div
from LEDAkem.ourGF2.util_function import trim_unnecessary_zeros, padding, transform_to_the_same_dim


def circulant_matrix_mod(a, b):
    a, b = trim_unnecessary_zeros(a), trim_unnecessary_zeros(b)

    fsize = len(a) + len(b) + 1

    fsize = 2 ** np.ceil(np.log2(fsize)).astype(int)  # use nearest power of two much faster

    fslice = slice(0, fsize)

    ta = np.fft.fft(a, fsize)
    tb = np.fft.fft(b, fsize)

    res = np.fft.ifft(ta * tb)[fslice].copy()

    k = np.mod(np.rint(np.real(res)).astype("uint64"), 2)

    out = gf2x_div(k, np.array([1] + (15013 - 1) * [0] + [1], dtype="uint8"))[1]

    # these operations are equal to do #np.mod(np.rint(np.real(np.fft.ifft(np.fft.fft(a) * np.fft.fft(b)))),2).astype("uint8")

    return trim_unnecessary_zeros(out)


def circulant_transpose(a, p):
    a_copy = np.copy(a)
    a_copy = padding(a_copy, p)

    a_copy[1:] = np.flip(a_copy[1:], axis=0)

    return a_copy


def circulant_matrix_mod_z(a, b):
    a, b = transform_to_the_same_dim(a, b)
    return np.rint(np.real(
        np.fft.ifft(np.fft.fft(a) * np.fft.fft(b))))


def z_add(a, b):
    a, b = trim_unnecessary_zeros(a), trim_unnecessary_zeros(b)

    N = len(a)

    D = len(b)

    if N == D:
        res = np.add(a, b)

    elif N > D:

        res = np.concatenate((np.add(a[:D], b), a[D:]))

    else:

        res = np.concatenate((np.add(a, b[:N]), b[N:]))

    return trim_unnecessary_zeros(res)