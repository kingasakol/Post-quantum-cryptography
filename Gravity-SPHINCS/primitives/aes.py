from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aesctr256(sk: bytes, counter: bytes, bytes_: int) -> bytes:
    size_of_buffer = 4096
    buffer = bytes.fromhex("00" * size_of_buffer)
    out = b''
    cipher = Cipher(algorithms.AES256(sk), modes.CTR(counter))
    encryptor = cipher.encryptor()
    while bytes_ > size_of_buffer:
        out += encryptor.update(buffer[:min(bytes_, 4096)])
        bytes_ -= size_of_buffer

    if bytes_ > 0:
        out += encryptor.update(buffer[:bytes_])
    return out


def aesctr256_zeroiv(sk: bytes, bytes_: int) -> bytes:
    return aesctr256(sk, bytes.fromhex("00" * 16), bytes_)
