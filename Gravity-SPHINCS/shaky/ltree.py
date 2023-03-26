from finished.hash import *


def ltree(buf: [Hash], count: int, root: [Hash]):
    src = buf[count]
    dst = buf[0]
    while count > 1:
        hashswap(src, dst)
        new_count = count >> 1
        hash_compress_pairs(dst, src, new_count)
        if count & 1:
            hashcpy(dst[new_count], src[count - 1])  # TODO potential bug dst[new_count]
            new_count += 1
        count = new_count
    hashcpy(root, dst)
