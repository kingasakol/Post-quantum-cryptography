from hashlib import sha3_256

import numpy as np

from LEDAkem.key_generation import key_generation
from LEDAkem.niederreiter_decrypt import decrypt_niederreiter
from LEDAkem.niederreiter_encrypt import encrypt_niederreiter
from LEDAkem.seed_expander import seed_expander
from LEDAkem.trng import trng

if __name__ == "__main__":
    # n0 =
    # p =
    # t =
    # sha3 = sha3_256
    # TRNG_byte_len

    pol = np.array([1] + (15013 - 1) * [0] + [1], dtype="uint8")
    pseed = trng(24)

    M = key_generation(trng(24), 2, 15013, 9, np.array([5, 4]), pol)

    s, c = encrypt_niederreiter(M, 2, 15013, 143, sha3_256, 24)

    threshold = seed_expander(None, None)

    res = decrypt_niederreiter(c, threshold, 20, pseed, 2, 15013, 9, np.array([5, 4]), sha3_256)

    print(res.hex())
    print(s.hex())
    print(s == res)
