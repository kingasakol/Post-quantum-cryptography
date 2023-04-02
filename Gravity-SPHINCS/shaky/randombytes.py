import secrets

from finished.hash import Hash
from utils.bytes_utils import bytes_to_int_list


def get_random_hash() -> Hash:
    return Hash(bytes_to_int_list(secrets.token_bytes(32)))
