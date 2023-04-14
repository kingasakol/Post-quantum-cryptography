import numpy as np

from LEDAkem.prng import binary_block_generate
from LEDAkem.trng import trng


def generate_H_Q_matrices(n0, p, dv, m, seed):
    m_copy = np.copy(m)

    H = []
    Q = []

    for i in range(n0):
        h = binary_block_generate(seed, p, dv)
        H.append(h)
        seed += b'1'

    #it should be 2 loops [[], []...[]]
    # może dałoby się zrobić to w poprzedniej pętli
    for i in range(n0):
        q_list = []
        for j in range(n0):
            q = binary_block_generate(seed, p, m_copy[j])
            q_list.append(q)
            seed + b'1'

        m_copy = np.roll(m_copy, 1)  #not sure if it is neccessary
        Q.append(q_list)

    return np.array(H, dtype=int), np.array(Q, dtype=int)





if __name__ == "__main__":
    H, Q = generate_H_Q_matrices(2, 24533, 13, np.array([5, 4]), trng(32))

    print(np.sum(H))
    print(np.sum(Q))