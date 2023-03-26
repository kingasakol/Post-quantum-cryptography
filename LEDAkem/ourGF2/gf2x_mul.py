import numpy as np
from LEDAkem.ourGF2.util_function import trim_unnecessary_zeros


def gf2x_mul(a, b):
    #wykorzystujemy FFT w celu przyspieszenia operacji mnożenia

    fsize = 2**np.ceil(np.log2((len(a) + len(b) - 1))).astype(int)
    fslice = slice(0, fsize)

    ta = np.fft.fft(a, fsize)
    tb = np.fft.fft(b, fsize)

    res = np.fft.ifft(ta * tb)[fslice].copy()
    k = np.mod(np.rint(np.real(res)), 2).astype('uint8')

    return trim_unnecessary_zeros(k)