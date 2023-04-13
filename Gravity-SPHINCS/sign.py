from gravity_sphincs.common import GRAVITY_c
from gravity_sphincs.gravity import gravity_gensk, gravity_genpk, GravityPK, GravitySign, GravitySK, gravity_sign, \
    gravity_verify
from gravity_sphincs.hash import Hash, hash_to_N
from gravity_sphincs.randombytes import get_random_hash
from utils.bytes_utils import int_list_to_bytes, bytes_to_int_list


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


def crypto_sign(m: bytes, sk: bytes) -> bytes:
    msg = Hash(bytes_to_int_list(hash_to_N(m)))
    g_sk = GravitySK.load(sk)
    sign = GravitySign()
    gravity_sign(g_sk, sign, msg)
    return len(m).to_bytes(32, 'big') + m + sign.save()


def crypto_sign_open(sm: bytes, pk: bytes) -> (bool, bytes):
    mlen = int.from_bytes(sm[:32], 'big')
    sm = sm[32:]
    pk = GravityPK(Hash(bytes_to_int_list(pk)))
    sig = GravitySign.load(sm[mlen:])
    m = sm[:mlen]
    msg = hash_to_N(m)
    return gravity_verify(pk, sig, Hash(bytes_to_int_list(msg)))
