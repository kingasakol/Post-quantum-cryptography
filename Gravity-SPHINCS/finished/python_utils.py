# [1, 2, 255] -> 0x0102FF
def int_list_to_bytes(l):
    b = [(x.to_bytes(1, "big")) for x in l]
    arr = b''
    for x in b:
        arr += x
    return arr


def bytes_to_int_list(b):
    return [b[i] for i in range(len(b))]


if __name__ == "__main__":
    print(int_list_to_bytes([1, 2, 255]))
    print(bytes_to_int_list(int_list_to_bytes([1, 2, 255])))
