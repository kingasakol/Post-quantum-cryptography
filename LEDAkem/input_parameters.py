from hashlib import sha3_256
import numpy as np


def parameters(category, n0):
    pol = None
    p = 0
    t = 0
    m = 0
    dv = 0
    byte_len = 0
    version_of_sha3 = None

    if category == 1:
        byte_len = 24
        version_of_sha3 = sha3_256

        if n0 == 2:
            p = 15013
            t = 143
            m = np.array([5, 4])
            dv = 9
        elif n0 == 3:
            p = 9643
            t = 90
            m = np.array([3, 2, 2])
            dv = 13
        elif n0 == 4:
            p = 8467
            t = 72
            m = np.array([3, 2, 2, 2])
            dv = 11
    elif category == 2 or category == 3:
        byte_len = 32

        from hashlib import sha3_384
        version_of_sha3 = sha3_384

        if n0 == 2:
            p = 24533
            t = 208
            m = np.array([5, 4])
            dv = 13
        elif n0 == 3:
            p = 17827
            t = 129
            m = np.array([4, 3, 2])
            dv = 15
        elif n0 == 4:
            p = 14717
            t = 104
            m = np.array([3, 2, 2, 2])
            dv = 15
    elif category == 4 or category == 5:
        byte_len = 40

        from hashlib import sha3_512

        version_of_sha3 = sha3_512

        if n0 == 2:
            p = 37619
            t = 272
            m = np.array([7, 6])
            dv = 11
        elif n0 == 3:
            p = 28477
            t = 172
            m = np.array([5, 4, 4])
            dv = 13
        elif n0 == 4:
            p = 22853
            t = 135
            m = np.array([4, 3, 3, 3])
            dv = 13


    pol = np.array([1] + (p - 1) * [0] + [1])
    return pol, p, t, m, dv, byte_len, version_of_sha3
