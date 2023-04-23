import numpy as np
from LEDAkem.ourGF2.util_function import trim_unnecessary_zeros


def gf2x_div(a, b):
    a_length = np.size(a) - 1
    b_length = np.size(b) - 1

    if a[a_length] == 0:
        a = trim_unnecessary_zeros(a)

    if b[b_length] == 0:
        b = trim_unnecessary_zeros(b)

    if not b.any():
        raise ZeroDivisionError("polynomial division")
    elif b_length > a_length:
        q = np.array([])
        return q, a
    else:
        u = a.astype("uint8")
        v = b.astype("uint8")

        m = len(u) - 1
        n = len(v) - 1
        scale = v[n].astype("uint8")
        q = np.zeros((max(m - n + 1, 1)), u.dtype)
        r = u.astype(u.dtype)

        for k in range(0, m - n + 1):
            d = scale and r[m - k].astype("uint8")
            q[-1 - k] = d
            r[m - k - n : m - k + 1] = np.logical_xor(r[m - k - n : m - k + 1], np.logical_and(d, v))

        r = trim_unnecessary_zeros(r)

    return q, r
