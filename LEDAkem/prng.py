import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha3_256, sha256

from LEDAkem.trng import trng


def binary_block_generate(seed, size, col_weight):
    arr = np.zeros(size, dtype= int) # maybe here should be dtype

    sha3_res, number, index = update_helper_params(seed, size, None, None)

    while np.sum(arr) != col_weight:
        arr[index] = 1
        sha3_res, number, index = update_helper_params(seed + sha3_res, size, sha3_res, number)

    return arr




def update_helper_params(seed, size, sha3_res = None, number = None):
    sha3_res = sha3_256(seed).digest()
    number = int.from_bytes(sha3_res, 'little')

    return sha3_res, number, number % size




# def aesctr256(sk: bytes, counter: bytes, bytes_: int) -> bytes:
#     size_of_buffer = 4096
#     buffer = bytes.fromhex("00" * size_of_buffer)
#     if bytes_ == 0:
#         raise Exception("AES unimplemented: bytes_ was 0")
#     out = b''
#     cipher = Cipher(algorithms.AES256(sk), modes.CTR(counter))
#     encryptor = cipher.encryptor()
#     while bytes_ > size_of_buffer:
#         out += encryptor.update(buffer[:min(bytes_, 4096)])
#         bytes_ -= size_of_buffer
#
#     if bytes_ > 0:
#         out += encryptor.update(buffer[:bytes_])
#
#     return out


if __name__ == "__main__":
    res = binary_block_generate(trng(24), 15013, 9)
    c = 0
    for i in res:
       if i == 1:
           c += 1
    print(c)