import numpy as np
from LEDAkem.ourGF2.util_function import trim_unnecessary_zeros
from LEDAkem.ourGF2.gf2x_add import gf2x_add
from LEDAkem.ourGF2.gf2x_div import gf2x_div


def gf2x_inv(f, g):
    out = gf2x_gcd(f, g)[0]
    return out

def gf2x_gcd(b, a):
    x1 = np.array([1], dtype="uint8")
    y0 = np.array([1], dtype="uint8")

    x0 = np.array([], dtype="uint8")
    y1 = np.array([], dtype="uint8")

    while True:

        q, r = gf2x_div(b, a)

        b = a

        if not r.any():
            break

        a = r

        if not (q.any() and x1.any()):  # if q is zero or x1 is zero
            x2 = x0
        elif not x0.any():  # if x0 is zero
            x2 = remainder_from_div(x1, q)
        else:
            mulres = remainder_from_div(x1, q)

            x2 = gf2x_add(x0, mulres)

        if not (q.any() and y1.any()):
            y2 = y0
        elif not y0.any():
            y2 = remainder_from_div(y1, q)
        else:
            mulres = remainder_from_div(y1, q)

            y2 = gf2x_add(y0, mulres)

        # update
        y0 = y1
        x0 = x1
        y1 = y2
        x1 = x2

    return y2, x2, b


def remainder_from_div(a, b):
    out = np.mod(np.convolve(a, b), 2).astype("uint8")
    return trim_unnecessary_zeros(out)


def gf2_inv(f, g):
    out = gf2_xgcd(f, g)[0]
    return out


def gf2_xgcd(b, a):
    x1 = np.array([1], dtype="uint8")
    y0 = np.array([1], dtype="uint8")

    x0 = np.array([], dtype="uint8")
    y1 = np.array([], dtype="uint8")

    while True:
        q, r = gf2x_div(b, a)
        b = a
        if not r.any():
            break

        a = r

        if not (q.any() and x1.any()):  # if q is zero or x1 is zero
            x2 = x0
        elif not x0.any():  # if x0 is zero
            x2 = mul(x1, q)
        else:
            mulres = mul(x1, q)
            x2 = gf2x_add(x0, mulres)

        if not (q.any() and y1.any()):
            y2 = y0
        elif not y0.any():
            y2 = mul(y1, q)
        else:
            mulres = mul(y1, q)
            y2 = gf2x_add(y0, mulres)

        # update
        y0 = y1
        x0 = x1
        y1 = y2
        x1 = x2

    return y2, x2, b


def mul(a, b):
    out = np.mod(np.convolve(a, b), 2).astype("uint8")
    return trim_unnecessary_zeros(out)
