# common.h

HASH_SIZE = 32
WOTS_LOG_ell1 = 6
WOTS_ell1 = 1 << WOTS_LOG_ell1 # WARNING may work differently in python! same for other << here
WOTS_chksum = 3
WOTS_ell = WOTS_ell1 + WOTS_chksum
WOTS_w = 16

PORS_k = 28
MERKLE_h = 5
GRAVITY_d = 10
GRAVITY_c = 14

PORS_tau = 16
PORS_t = (1 << (PORS_tau))

MERKLE_hhh = (1 << (MERKLE_h))

GRAVITY_ccc = (1 << (GRAVITY_c))
GRAVITY_h = ((MERKLE_h) * (GRAVITY_d) + (GRAVITY_c))

#GRAVITY_mask = ~(0xFFFFFFFFFFFFFFFF << (GRAVITY_h))
#GRAVITY_mask = 0xFFFFFFFFFFFFFFFF
# TODO ogarnij

LOG_MAX_BATCH_COUNT = 10
MAX_BATCH_COUNT = (1 << (LOG_MAX_BATCH_COUNT))


GRAVITY_OK = 0
GRAVITY_ERR_VERIF = 1
GRAVITY_ERR_ALLOC = 2
GRAVITY_ERR_BATCH = 3
