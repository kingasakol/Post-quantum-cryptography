import numpy as np
from LEDAkem.ourGF2.util_function import trim_unnecessary_zeros


def xor(a, b):
    return np.logical_xor(a, b).astype("uint8")


def gf2x_add(a, b):
    a, b = check_type(a, b)
    a = trim_unnecessary_zeros(a)
    b = trim_unnecessary_zeros(b)
    N = len(a)
    D = len(b)

    if N == D:
        res = xor(a, b)
    elif N > D:
        res = np.concatenate((xor(a[:D], b), a[D:]))
    else:
        res = np.concatenate((xor(a, b[:N]), b[N:]))

    return trim_unnecessary_zeros(res)


def check_type(a, b):
    if isinstance(a, np.ndarray):
        a = np.array(a, dtype="uint8")
    if isinstance(b, np.ndarray):
        b = np.array(b, dtype="uint8")

    if a.dtype != "uint8":
        a = a.astype("uint8")

    if b.dtype != "uint8":
        b = b.astype("uint8")

    return a, b