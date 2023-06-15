from LEDAkem.H_Q_matrices_generation import generate_H_Q_matrices
from LEDAkem.circulant_matrix_helper import circulant_matrix_mod
from LEDAkem.ourGF2.gf2x_add import gf2x_add
from LEDAkem.ourGF2.gf2x_inv import gf2x_inv
from LEDAkem.trng import trng
import numpy as np


def key_generation(seed, n0, p, dv, m, polynomial):
    H, Q = generate_H_Q_matrices(n0, p, dv, m, seed)

    L = []

    for i in range(n0):
        l = np.zeros(p, dtype=int)
        for j in range(n0):
            l = gf2x_add(l, circulant_matrix_mod(H[j], Q[j, i], polynomial))
        L.append(l)

    L_inv = gf2x_inv(L[-1], polynomial)  # LEDAkem_GLOBAL_PARAMS.irr_poly

    M = []

    for i in range(n0 - 1):
        m = circulant_matrix_mod(L_inv, L[i], polynomial)
        M.append(m)

    return M


if __name__ == "__main__":
    pol = np.array([1] + (15013 - 1) * [0] + [1], dtype="uint8")
    res = key_generation(trng(24), 2, 15013, 9, np.array([5, 4]), pol)
    print(res[0].sum())
