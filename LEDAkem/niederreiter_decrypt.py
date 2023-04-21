import numpy as np

from LEDAkem.H_Q_matrices_generation import generate_H_Q_matrices
from LEDAkem.circulant_matrix_helper import circulant_matrix_mod, circulant_transpose, z_add, circulant_matrix_mod_z
from LEDAkem.ourGF2.gf2x_add import gf2x_add
from LEDAkem.ourGF2.util_function import padding
from LEDAkem.prng import binary_block_generate


# def decrypt_niederreiter(c, seed_exp, i_max, seed, n0, p, dv, m, sha3):
#     H, Q = generate_H_Q_matrices(n0, p, dv, m, seed)
#
#     L = np.zeros(p, dtype='uint8')
#
#     for i in range(n0):
#         circmp = circulant_matrix_mod(H[i], Q[i][n0 - 1])
#         L = gf2x_add(L, circmp)
#
#     s = circulant_matrix_mod(L, c)
#     s = circulant_transpose(s, p)
#
#     res_from_q_decoder = Q_decoder(H, Q, n0, p, s, seed_exp, i_max)
#
#     return sha3(res_from_q_decoder[1]).digest()
#
#
#
# #todo read specification !!!
#
# def Q_decoder(H, Q, n0, p, s, seed_exp, i_max):
#     i_iter = 1
#
#     e = np.zeros(n0 * p, dtype='uint8')
#     e = np.reshape(e, (n0, p))
#
#     s_i = s
#
#     while (i_iter < i_max) and (s_i.any()):
#         counter = []
#         for i in range(n0):
#             counter.append(circulant_matrix_mod_z(s_i, (H[i])))
#
#
#         corr = []
#         for i in range(n0):
#             corr.append(circulant_matrix_mod_z(counter[0], Q[0, i]))
#             for j in range(1, n0):
#
#                  corr[i] = z_add(corr[i], circulant_matrix_mod_z(counter[j], (Q[j, i])))
#
#         ws = np.count_nonzero(s_i)
#
#         pos =  np.where(seed_exp[:, 0] < ws)[0]
#
#         b = seed_exp[pos[-1], 1]
#
#         for i in range(n0):
#             pos = np.where(corr[i] >= b)[0]
#             e[i, pos] = np.logical_not(e[i, pos])
#
#
#         ep = []
#         for i in range(n0):
#
#             temp = np.zeros(p, dtype='uint8')
#
#             for j in range(n0):
#                 temp = gf2x_add(temp, circulant_matrix_mod(e[j, :], circulant_transpose(Q[i, j], p)))
#
#             ep.append(temp)
#
#         delta_s = np.zeros(p, dtype='uint8')
#         for i in range(n0):
#             delta_s = gf2x_add(delta_s, circulant_matrix_mod(ep[i], circulant_transpose(H[i], p)))
#
#         s_i = gf2x_add(s, delta_s)
#         i_iter += 1
#
#     if i_iter == i_max:
#         flag = False
#     else:
#         flag = True
#
#         for i in range(n0):
#             e[i] = padding(e[i], p)
#
#     return flag, e


######################################################
# def decrypt_niederreiter(c, seed_exp, i_max, seed, n0, p, dv, m, sha3):
def leda_dec(c, thresh_lut, i_max, pseed, n0, p, dv, m, sha3):


    H, Q = HQgen(n0, p, dv, m, pseed)

    Llast = np.zeros(p, dtype='uint8')

    for i in range(n0):
        Llast = gf2x_add(Llast, circulant_matrix_mod(H[i], Q[i][n0 - 1]))

    s1 = circulant_matrix_mod(Llast, c)

    s2 = circulant_transpose(s1, p)  #TODO transpose Q e H instead in Qdecoder

    ok, e = Qdecoder(H, Q, n0, p, s2, thresh_lut, i_max)

    Ks = sha3(e).digest()

    return ok, Ks



def HQgen(n0, p, dv, m, pseed):
    m = np.copy(m)  # avoid changing

    H = []
    for i in range(n0):
        temp = binary_block_generate(pseed, p, dv) # NB actual specification requires NIST secure AES based PRNG
        H.append(temp)
        pseed = pseed + b'1'

    Q = []

    for i in range(n0):

        Q_col = []

        for j in range(n0):
            Q_submat = binary_block_generate(pseed, p, m[j])
            Q_col.append(Q_submat)
            pseed = pseed + b'1'

        m = np.roll(m, 1)

        Q.append(Q_col)

        # print(np.sum(H))
        # print(np.sum(Q))

    return np.array(H, dtype='uint8'), np.array(Q, dtype='uint8')


def Qdecoder(H, Q, n0, p, s, look_up, i_max):
    i_iter = 1

    e = np.zeros(n0 * p, dtype='uint8')
    e = np.reshape(e, (n0, p))

    s_i = s

    while (i_iter < i_max) and (s_i.any()):  # syndrome not zeros

        counter = []
        for i in range(n0):
            counter.append(circulant_matrix_mod_z(s_i, (H[i])))


        corr = []
        for i in range(n0):
            corr.append(circulant_matrix_mod_z(counter[0], Q[0, i]))
            for j in range(1, n0):

                 corr[i] = z_add(corr[i], circulant_matrix_mod_z(counter[j], (Q[j, i])))

        ws = np.count_nonzero(s_i)

        pos =  np.where(look_up[:, 0] < ws)[0]

        b = look_up[pos[-1], 1]

        for i in range(n0):
            pos = np.where(corr[i] >= b)[0]
            e[i, pos] = np.logical_not(e[i, pos])


        ep = []
        for i in range(n0):

            temp = np.zeros(p, dtype='uint8')

            for j in range(n0):
                temp = gf2x_add(temp, circulant_matrix_mod(e[j, :], circulant_transpose(Q[i, j], p)))

            ep.append(temp)

        delta_s = np.zeros(p, dtype='uint8')
        for i in range(n0):
            delta_s = gf2x_add(delta_s, circulant_matrix_mod(ep[i], circulant_transpose(H[i], p)))

        s_i = gf2x_add(s, delta_s)
        i_iter += 1

    if i_iter == i_max:
        flag = False
    else:
        flag = True

        for i in range(n0):
            e[i] = padding(e[i], p) #pad each block of e to have p length

    return flag, e