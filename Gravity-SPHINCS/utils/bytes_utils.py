# [1, 2, 255] -> 0x0102FF
def int_list_to_bytes(l: [int]) -> bytes:
    b = [(x.to_bytes(1, "big")) for x in l]
    arr = b''
    for x in b:
        arr += x
    return arr


def bytes_to_int_list(b: bytes) -> [int]:
    return [*b]

