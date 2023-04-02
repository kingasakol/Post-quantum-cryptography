from finished.common import GRAVITY_c
from finished.gravity import gravity_gensk, gravity_genpk, GravityPK, GravitySign, GravitySK
from finished.hash import Hash
from shaky.randombytes import get_random_hash
from utils.bytes_utils import int_list_to_bytes


def crypto_sign_keypair(seed=None, salt=None) -> (bytes, bytes):
    if not seed:
        seed = get_random_hash()
    if not salt:
        salt = get_random_hash()

    g_sk = GravitySK(seed, None, salt)
    gravity_gensk(g_sk)
    g_pk = GravityPK()
    gravity_genpk(g_sk, g_pk)
    return int_list_to_bytes(g_pk.k.h), g_sk.save()


def crypto_sign_keypair_test():
    seed = Hash([i for i in range(32)])
    salt = Hash([32 - i for i in range(32)])
    pk, sk = crypto_sign_keypair(seed, salt)
    if pk.hex() != "a73e2eb8e10194f424bdafd86ad6c89cf90b9849fe19aeca38c9668512eac6a2":
        raise Exception("Test failed")
    if sk.hex() != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020120b97e26ac1c97d2cba431e1c75a6909b743bb7cf260dc076929e2a842ffb90543eb2967250331694e7aea03dc339f3b46809382f0c659951f6dae0b557da014a73e2eb8e10194f424bdafd86ad6c89cf90b9849fe19aeca38c9668512eac6a2":
        raise Exception("Test failed")


if __name__ == "__main__":
    if GRAVITY_c != 1:
        raise Exception("To run tests set GRAVITY_c to 1")
    crypto_sign_keypair_test()

    print("OK")

'''
int crypto_sign (unsigned char *sm,
                 unsigned long long *smlen,
                 const unsigned char *m,
                 unsigned long long mlen,
                 const unsigned char *sk) {

    struct gravity_sk sk_str;
    struct hash msg;
    struct gravity_sign sig;
    int ret;

    if (!sm || !smlen || !m || !sk) return -1;

    hash_to_N (&msg, m, mlen);

    memcpy ((void *)&sk_str, sk, sizeof (struct gravity_sk));

    memset ((uint8_t *)(&sig), 0, sizeof (struct gravity_sign));

    ret = gravity_sign (&sk_str, &sig, &msg);

    if (ret != GRAVITY_OK) return ret;

    memcpy (sm + mlen, (uint8_t *)(&sig), sizeof (struct gravity_sign));

    memmove (sm, m, mlen);
    *smlen = mlen + sizeof (struct gravity_sign);

    return 0;
}

int crypto_sign_open (unsigned char *m,
                      unsigned long long *mlen,
                      const unsigned char *sm,
                      unsigned long long smlen,
                      const unsigned char *pk) {

    struct gravity_pk pk_str;
    struct hash msg;
    struct gravity_sign sig;

    if (!m || !mlen || !sm || !pk) return -1;

    if (smlen < sizeof (struct gravity_sign)) return -2;

    *mlen = smlen - sizeof (struct gravity_sign);

    memcpy ((void *)(&pk_str), pk, HASH_SIZE);

    memcpy ((void *)&sig, sm + *mlen, sizeof (struct gravity_sign));

    memcpy (m, sm, *mlen);

    hash_to_N (&msg, m, *mlen);

    return gravity_verify (&pk_str, &sig, &msg);
}
'''
