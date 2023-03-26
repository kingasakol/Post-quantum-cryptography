import numpy as np
from LEDAkem.ourGF2.util_function import trim_unnecessary_zeros


def xor(a, b):
    return np.logical_xor(a, b).astype("uint8")


def gf2x_add(a, b):
    # a, b = check_type(a, b)

    a, b = trim_unnecessary_zeros(a), trim_unnecessary_zeros(b)

    N = len(a)
    D = len(b)

    if N == D:
        res = xor(a, b)
    elif N > D:
        res = np.concatenate((xor(a[:D], b), a[D:]))
    else:
        res = np.concatenate((xor(a, b[:N]), b[N:]))

    return trim_unnecessary_zeros(res)