from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aesctr256(sk, counter, bytes_):
    print("AES info: bytes_ = ", bytes_)
    if bytes_ != 16:
        print("AES warning: are those bytes_ ok?")
    size_of_buffer = 4096  # TODO static ?
    buffer = bytes.fromhex("00" * size_of_buffer)
    if bytes_ == 0:
        raise Exception("AES unimplemented: bytes_ was 0")

    cipher = Cipher(algorithms.AES256(sk), modes.CTR(counter))
    encryptor = cipher.encryptor()
    while bytes_ > size_of_buffer:  # TODO this mat work strange and can cause bugs
        out = encryptor.update(buffer[:bytes_])
        out += size_of_buffer
        bytes_ -= size_of_buffer

    if bytes_ > 0:
        out = encryptor.update(buffer[:bytes_])

    # TODO ADD FINAL
    print("AES returned: " + out.hex())
    return out


def aesctr256_zeroiv(sk, bytes_):
    return aesctr256(sk, bytes.fromhex("00" * 16), bytes_)


if __name__ == "__main__":
    print(aesctr256(bytes.fromhex("00" * 32), bytes.fromhex("00" * 16), 16).hex())
    print(aesctr256(bytes.fromhex("0F" * 32), bytes.fromhex("01" * 16), 16).hex())
    print(aesctr256_zeroiv(bytes.fromhex("FF" * 32), 16).hex())

    '''
    dc95c078a2408989ad48a21492842087
    16da6f2995c1848346af60eab5a45a5c
    4bf85f1b5d54adbc307b0a048389adcb
    '''
