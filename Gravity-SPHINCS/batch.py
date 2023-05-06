from gravity_sphincs.common import MAX_BATCH_COUNT, LOG_MAX_BATCH_COUNT
from gravity_sphincs.hash import Hash, hash_to_N, hashcpy, hash_compress_pairs
from gravity_sphincs.merkle import merkle_compress_auth
from utils.bytes_utils import bytes_to_int_list


class BatchBuf:
    def __init__(self):
        self.buf = [Hash() for _ in range(MAX_BATCH_COUNT)]
        self.count = 0


class BatchGroup:
    def __init__(self):
        self.tree = [Hash() for _ in range(2 * MAX_BATCH_COUNT - 1)]
        self.count = None


class BatchAuth:
    def __init__(self):
        self.auth = [Hash() for _ in range(LOG_MAX_BATCH_COUNT)]
        self.index = None


def batch_append(buf: BatchBuf, msg: bytes) -> int:
    if buf.count == MAX_BATCH_COUNT:
        raise Exception('MAX BATCH COUNT reached')
    buf.buf[buf.count] = Hash(bytes_to_int_list(hash_to_N(msg)))
    buf.count += 1
    return buf.count


def batch_group(group: BatchGroup, buf: BatchBuf) -> None:
    height = LOG_MAX_BATCH_COUNT
    n = 1 << height
    offset = n - 1
    count = buf.count
    if count == 0:
        raise Exception('Empty batch')
    group.count = count

    for i in range(count):
        group.tree[offset + i].h = buf.buf[i].h.copy()

    for i in range(count, n):
        hashcpy(group.tree[offset + i], buf.buf[0])

    while height > 0:
        offset >>= 1
        height -= 1
        hash_compress_pairs(group.tree, offset, offset, 1 << height)


def batch_extract(group: BatchGroup, auth: BatchAuth, index: int) -> None:
    height = LOG_MAX_BATCH_COUNT
    n = 1 << height
    offset = n - 1

    count = group.count
    if index >= count:
        raise Exception('Index greater than count')

    auth.index = offset + index

    for i in range(height):
        sibling = index ^ 1
        hashcpy(auth.auth[i], group.tree[offset + sibling])
        index >>= 1
        offset >>= 1


def batch_compress_auth(auth: BatchAuth, msg: bytes) -> Hash:
    height = LOG_MAX_BATCH_COUNT
    node = Hash(bytes_to_int_list(hash_to_N(msg)))
    merkle_compress_auth(node, auth.index, auth.auth, height)
    return node
