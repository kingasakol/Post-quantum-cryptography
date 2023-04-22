from LEDAkem.key_generation import key_generation
from LEDAkem.niederreiter_decrypt import decrypt_niederreiter
from LEDAkem.niederreiter_encrypt import encrypt_niederreiter
from LEDAkem.seed_expander import seed_expander
from LEDAkem.input_parameters import parameters
from LEDAkem.trng import trng

if __name__ == "__main__":

    n0 = 4
    category = 2
    i_max = 20

    parameters = parameters(category, n0)
    pol = parameters[0]
    p = parameters[1]
    t = parameters[2]
    m = parameters[3]
    dv = parameters[4]
    byte_len = parameters[5]
    version_of_sha3 = parameters[6]

    pseed = trng(byte_len)

    M = key_generation(pseed, n0, p, dv, m, pol)

    s, c = encrypt_niederreiter(M, n0, p, t, version_of_sha3, byte_len, pol)
    threshold = seed_expander(category, n0)

    res = decrypt_niederreiter(c, threshold, i_max, pseed, n0, p, dv, m, version_of_sha3, pol)

    print(res.hex())
    print(s.hex())
    print(s.hex() == res.hex())
