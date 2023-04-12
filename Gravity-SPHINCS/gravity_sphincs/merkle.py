from gravity_sphincs.hash import Hash, Address, hash_2N_to_N
from gravity_sphincs.wots import WotsSign, WotsSK, LwotsPK, wots_gensk, lwots_genpk, wots_sign, lwots_extract
from gravity_sphincs.common import MERKLE_h, MERKLE_hhh, HASH_SIZE, GRAVITY_OK, WOTS_ell, GRAVITY_ERR_VERIF
from utils.hash_utlis import list_of_hashes_to_bytes


class MerklePK:
    def __init__(self):
        self.k = Hash()


class MerkleSign:
    def __init__(self, src=None):
        if src:
            self.wots = WotsSign(src)
            self.auth = [Hash(src[HASH_SIZE * (WOTS_ell + i): HASH_SIZE * (WOTS_ell + i + 1)]) for i in range(MERKLE_h)]
        else:
            self.wots = WotsSign()
            self.auth = [Hash() for _ in range(MERKLE_h)]

    def __eq__(self, other):
        if isinstance(other, MerkleSign):
            if self.wots != other.wots:
                return False
            for i in range(MERKLE_h):
                if self.auth[i] != other.auth[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return f'MERKLE SIGN: {{ wots: {self.wots}, auth: {self.auth}}}'

    def hex(self):
        return list_of_hashes_to_bytes(self.wots.s).hex() + list_of_hashes_to_bytes(self.auth).hex()

    def bytes(self):
        return list_of_hashes_to_bytes(self.wots.s) + list_of_hashes_to_bytes(self.auth)

    @staticmethod
    def size():
        return WotsSign.size() + HASH_SIZE * MERKLE_h

    @staticmethod
    def load(merkle: [int]) -> 'MerkleSign':
        res = MerkleSign()
        for i in range(WOTS_ell):
            res.wots.s[i] = Hash(merkle[HASH_SIZE * i: HASH_SIZE * (i + 1)])
        for i in range(MERKLE_h):
            res.auth[i] = Hash(merkle[WotsSign.size() + i * HASH_SIZE: WotsSign.size() + (i + 1) * HASH_SIZE])
        return res


# util - performs hash_compress_pairs but uses "continuous memory" and "pointers"
def hash_compress_pairs_one_list(src: [Hash], id_1: int, id_2: int, n: int):
    for i in range(n):
        src[id_1 + i] = hash_2N_to_N(src[id_2 + 2 * i], src[id_2 + 2 * i + 1])


def merkle_alloc_buf(n: int) -> [None]:
    return [None for _ in range(2 * (1 << n))]


def merkle_sign_list_to_bytes(signs: [MerkleSign]) -> bytes:
    res = b''
    for s in signs:
        res += s.bytes()
    return res


# TESTED
def merkle_genpk(key: Hash, address: Address, pk: MerklePK):
    index = address.index & (MERKLE_hhh - 1)
    base_address = Address(address.index - index, address.layer)
    wsk = WotsSK()
    wpk = LwotsPK()
    buf = merkle_alloc_buf(MERKLE_h)

    # leaves
    for j in range(MERKLE_hhh):
        wots_gensk(key, base_address, wsk)
        lwots_genpk(wsk, wpk)
        buf[j] = Hash(wpk.k.h.copy())
        base_address.index += 1

    merkle_compress_all(buf, MERKLE_h, pk.k)


# TESTED
def merkle_sign(key: Hash, address: Address, sign: MerkleSign, msg: Hash, pk: MerklePK) -> int:
    wsk = WotsSK()
    wpk = LwotsPK()
    index = address.index & (MERKLE_hhh - 1)
    base_address = Address(address.index - index, address.layer)
    buf = merkle_alloc_buf(MERKLE_h)

    for j in range(MERKLE_hhh):
        wots_gensk(key, base_address, wsk)
        lwots_genpk(wsk, wpk)
        buf[j] = Hash(wpk.k.h.copy())
        base_address.index += 1

        if j == index:
            wots_sign(wsk, sign.wots, msg)

    merkle_gen_auth(buf, MERKLE_h, sign.auth, index, None if pk is None else pk.k)
    return GRAVITY_OK


# TESTED
def merkle_extract(pk: MerklePK, address: Address, sign: MerkleSign, msg: Hash):
    wpk = LwotsPK()
    index = address.index & (MERKLE_hhh - 1)

    lwots_extract(wpk, sign.wots, msg)

    merkle_compress_auth(wpk.k, index, sign.auth, MERKLE_h)
    pk.k.h = wpk.k.h.copy()


# todo operates on buf in c-like pointer style
# TESTED BY TRANSITION
def merkle_compress_all(buf: [Hash], height: int, root: Hash):
    n = 1 << height
    src_id = 0
    dst_id = 0
    for l in range(height):
        src_id, dst_id = dst_id, src_id
        n >>= 1
        hash_compress_pairs_one_list(buf, dst_id, src_id, n)

    root.h = buf[dst_id].h.copy()


# todo operates on buf in c-like pointer style
# TESTED BY TRANSITION
def merkle_gen_auth(buf: [Hash], height: int, auth: [Hash], index: int, root: Hash):
    n = 1 << height
    # inlining those below:
    src_id = n
    dst_id = 0
    for l in range(height):
        sibling = index ^ 1
        auth[l] = Hash(buf[dst_id + sibling].h.copy())
        index >>= 1
        src_id, dst_id = dst_id, src_id
        n >>= 1
        hash_compress_pairs_one_list(buf, dst_id, src_id, n)
    # Public key
    if root is not None:
        root.h = buf[dst_id].h.copy()


# TESTED BY TRANSITION
def merkle_compress_auth(node: Hash, index: int, auth: [Hash], height_diff: int) -> int:
    for l in range(height_diff):
        if index % 2 == 0:
            node.h = hash_2N_to_N(Hash(node.h.copy()), Hash(auth[l].h.copy())).h
        else:
            node.h = hash_2N_to_N(Hash(auth[l].h.copy()), Hash(node.h.copy())).h
        index >>= 1

    return index


# todo operates on buf in c-like pointer style,
# returns octolen as int is primitive
# TESTED BY GRAVITY SIGN
def merkle_gen_octopus(buf: [Hash], height: int, octopus: [Hash], root: Hash, indices: [int], count: int) -> int:
    n = 1 << height
    src_id = n
    dst_id = 0
    length = 0

    for l in range(height):
        i = 0
        j = 0
        # Copy auth octopus
        while i < count:
            index = indices[i]
            sibling = index ^ 1
            # Check redundancy with sibling
            if (i + 1) < count and indices[i + 1] == sibling:
                i += 1
            else:
                octopus[length].h = buf[dst_id + sibling].h.copy()
                length += 1
            indices[j] = indices[i] >> 1
            i += 1
            j += 1
        # Update count of non-redundant nodes
        count = j
        dst_id, src_id = src_id, dst_id
        n >>= 1
        # compute all hashes at current layer
        hash_compress_pairs_one_list(buf, dst_id, src_id, n)

    root.h = buf[dst_id].h.copy()
    return length


# TODO RETURNS INT
# TESTED BY GRAVITY_VERIFY
def merkle_compress_octopus(nodes: [Hash], height: int, octopus: [Hash], octolen: int, indices: [int],
                            count: int) -> int:
    length = 0
    buf = [None, None]
    for l in range(height):
        i = 0
        j = 0
        while i < count:
            index = indices[i]
            if index % 2 == 0:
                buf[0] = Hash(nodes[i].h.copy())
                if (i + 1) < count and indices[i + 1] == index + 1:
                    i += 1
                    buf[1] = Hash(nodes[i].h.copy())
                else:
                    if length == octolen:
                        return GRAVITY_ERR_VERIF
                    buf[1] = Hash(octopus[length].h.copy())
                    length += 1
            else:
                if length == octolen:
                    return GRAVITY_ERR_VERIF
                buf[0] = Hash(octopus[length].h.copy())
                length += 1
                buf[1] = Hash(nodes[i].h.copy())
            nodes[j] = hash_2N_to_N(buf[0], buf[1])
            indices[j] = indices[i] >> 1
            i += 1
            j += 1
        count = j
    if length != octolen:
        return GRAVITY_ERR_VERIF
    return GRAVITY_OK


# ------------------------------------- TEST UTILS:

def merkle_genpk_sample():
    k = Hash([i for i in range(32)])
    a = Address(1, 2)
    pk = MerklePK()
    merkle_genpk(k, a, pk)
    return pk


def merkle_genpk_test():
    pk = merkle_genpk_sample()
    expected = "1603e9132467982229c6375d206f5631e8dca70c490bbed6002cdf1958c8e3c3"
    if pk.k.to_bytes().hex() != expected:
        raise Exception("Test failed")


def merkle_sign_sample():
    pk = merkle_genpk_sample()
    key = Hash([i + 2 for i in range(32)])
    address = Address(1, 2)
    sign = MerkleSign()
    msg = Hash([50 - i for i in range(32)])
    merkle_sign(key, address, sign, msg, pk)
    if pk.k.to_bytes().hex() != "aec33cd1c1a4d1d5ea80d80f7d55d098e74db406e764a92d260f0cf183ae4e1e":
        raise Exception("Test failed")
    return sign


def merkle_sign_test():
    sign = merkle_sign_sample()
    expected_auth = "702cc2cb7ef4ca3a9b246eca808579f4a3e5ff18ed0a070c00305a445be15872efd206b4979f3eb4deceb0264c5b7c083df6d594c30d7cadae93af52d1ab5a11e3bde6c0cbb24b696fc0bca280aba861abef7d2a3224ad734d86ddea0287accbf31aad740b4e7123b21d0eb460b8d46ae1053516b74ef55c51ffeed9c139b70f56399e478b628e611198a5671c510ef67658f98d3540511665ece9322128f6c4"
    expected_wots = "6a9e8ad255044b3634d3e6de23ec6099f16e9b051227fb9a15922e71822c35917ba0535cf6a979dd687d3f0d28b6b2fd84a3e49d342b8a703c41047e6101a6992687d7d5051a77b08fb405fce86a361ccf602c8b109cfccb167b3b62b9d919749e872655fd929b56eaa548f35bfb22dd1963473e290029a4087bb27cd6ed1ebd51c49aef98f6d973e5817244b9643cc9e8eb4f195ffc2d3c2fefef63b3cc7e2ea094fb5a4cfae37d168dcbbb960593fc889da802fd27d0decd8a75cad6686dba9255fef724ac7ed155c0186a065dde80882f704b81579eecd6d7ee7abdfe117aff2b907b87a3612c311e63d4bb0582c90dba778357b83cd1f690df07087b27bcacf3db96747a0adbc9fc1606e36339c34411df5d42f076f8c51a7d7e8f8dbe9a0612552088f3d52311f4978791f759980600c9a38152e0dcc51b7576d8c54075f2027214860c9dfbd1d40d47be5d4a969e663176bdf640284529e5c890a669259141d19422366a902285a2d52d686440890c7da65394c8358220f3ba102486f9efd53a9a6f94ffd85cc6faf33062f81d06e4e73b03f1b037aa491a573012cbec87416529fda6b5381023a552d70e9943cf668de0d1e3f8b2e0ff88913c500e4c0a28d3b18fd3a185197ad2facbfcf770ce621a3173d17afcf145e394a5d1a493d3c1050d51ca58f2c2b6adf9a9ab0dfeeeba45631275dd9b1368a34b12fea9a0b7257652c6e9fd796246b9dfd0c6832bd37a4cedc0f4d36b45d314adc7de8fa220a8e740ec13323802ad479584111cbe6de4f5fc067fb31f5c4a042e5bd9a60b78cb5942c6c6c1aca5fdc8a00ba7763de9dff58df993ef2931a3b8bd6675e41c3f27cdc803a46456b7e3e19173ba07fc0a40897968686da53dede8421c9721a2a1911cc76f0ce91dcdd455491b8b5ebe4d9a6807e1ff9cee1fa47a8c2643b8aaf0dc846d73688b87dc6c6b7984ba2d20e95d74835126ea89204c3ffb1f5af011bf18489f8fbbe9ffed132b8595ace839491b42a89b2f046998cb2a70b91bb8a3cd4258707df8a9af05907634306bb8ec5b14ed3a4c58fcd4a6302463f84183947027a0b21d4f315d8f654b7d2f4881f282279eb48665c0d0dba706b9b546f99fc1170a3342dd611196f683891420d096d4d96b2ed23db3144604ede53a593c30ce56562d094145f02493e5a7749ce0150ea0986af2eaff90e22de4af725bfdc43ddfbf9d6a9f1a43676fba77d50506d2c854a8af485b773a4638654d621d2b129cb5ce74caf2cf3081ffe731d627a917590457f4a2e29592ff147a5d08132e3642a2c99ea6837ba72c7c14db6193a5f89ca2adf05e99866513d642fe96d12e0f39cee244b0d62997b0374fb23f271d36e516f20c7c6b3ca80be115d2d1a6730e57000682618571e5a5a8319959fb0eb531a5c05b61d4318ca77579b34020fa92078823df49c5becb3f6ba303f911fc543525171b69387f03da30ce4f223aeb35e666edc66844a5d896108e4e27aaa8747d08aa660eda51ef0366ddc060d9d58b8c796c96a4ea90fee39f75e2adcf6fa0b0f54ac9bee173ffacc50a98ef2bb6f1465a136c81e4521ab1710351dba93f14e6eedcab7bf2a897960a123cc918f8b1567fda637145bdd7a1dd074fb914760b8502d4e28b7ccd62eb9d4e07c4cf03bc4689ceee51255377a2f3e201d8b479f28886a2853febe31b7985567a1fba3f25344868d38660611d94db01fbeb251a4a4384c50bb6c6834b163e486ee332cfbad3048246078fce8cb82fd59fce68f5b29026ebb34a6bcf95623fc46ede44f807c0f33752d3ce7ed3ce88039b08550f5d2dcb28e98b9c871cfc394142ba483a31e6e1ca3f02e066fced9616c179c7f1e505f97f8ec255d7640f6a53dfef3cb677d2ce145de9b981246608f3e4762af88576209fd5e6a4dd36a0fc9077287ebae390b5bd9047540d4d4d107cb5b3fdfe805b9e92ead642d50753e757c8bf55b37fbab4c557858851700e2f2b9db69939029276bde14203f70ba34c17c8def42fef35e604102d9956275a69ce4abe008c113eca1a42ceaa453f0e6c73c1cc1cea5d91195b6619d2adaf531e9ac52ca448759f6126977098e506be83153eccc293cfcb40c4f9fedfffe9bff2ae2bee461af05b739f119c14598da92fb8700f1c36f54e23ec7acd330d6d53be07810c774c4a36eda1b810eba88831e1dc14c1b8c525f1d7f5d9b0aedecaa5292b3ebb48a9210c1a27687497385e54a50e460399a0fc78fe6637b34d1dcc94a0d24003be8698d30e2a20f29cceaab31ea7a4c3250bc8dd4531fdd2c1712da436d93ca8d98ee35ec963ed5ba5a6c20b1556eb08035e1c16b9fabebe6d8a0131b70527b1cf5837728c12cf4556cc1e7e775afb862f6a6496de31f6683a97e76d9f3b091303efd75dd1e7c8f1b1e0df4f915a89f43ffcf8b2cb70b39444756a9ab0f42fd085830e4f48d6b4f5ba4d7aaf792c58634aa45c740825e1815720dd5ed615af3552c41902fa4d6419e74950ac584297fedc6733e778283d17b4884e82d9b145c01d944c78c774c20d70aef8b4105f1f0724a9d57eb7a6487799ec97fc2195266d566ed2c231671f1aa3e8284b5c32ec3ddd6b0bc7672d2070730a8ec763f8538d38934161347b474b18906929c125f3689f63c5834649e059e82abb60f86a2f74c71c7ea866f4e94f8ef0b61e22da65025eb8a3458c6d0562b4120e7977d275073744745189729082e2e2c0ad77ecbf27aa55e1452f5f43666f712490b86ebd614d4d64476bfee15c00f251726a5db26117d244bfff874cfcda2931ff3348668b398b380aa0400a4d751654d08f623a9bc6b8914abe9418f9407485e34668bd6e0268e80638a4782ed8ff78c795aa627b6a199ddc8e4bcc240d3f3b77275526c77c9612fa3912d3397a704b2452d69827686a3697371dc83d5e5918e92c40830de8dc06770c52c714a7121e79d6f731a6d7f2d607da95ca2b869f9f230ee6a21ef25172fe8fda0133c2e1c4158ae50606c47975"
    auth = ""
    for i in range(MERKLE_h):
        auth += (sign.auth[i].to_bytes().hex())
    wots = ""
    for i in range(WOTS_ell):
        wots += (sign.wots.s[i].to_bytes().hex())
    if auth != expected_auth:
        raise Exception("Test failed")
    if wots != expected_wots:
        raise Exception("Test failed")


def merkle_extract_test():
    sign = merkle_sign_sample()
    adr = Address(1, 2)
    msg = Hash([i for i in range(32)])
    pk = MerklePK()
    merkle_extract(pk, adr, sign, msg)
    expected = "e754635abcd170df8bbe469c29ecf2b265096e5fe13b89f0a412aedd85fa6e13"
    if pk.k.to_bytes().hex() != expected:
        raise Exception("Test failed")


if __name__ == "__main__":
    # those are quite slow (be worried only if nothing updates in ~3 mins)
    merkle_extract_test()
    print("33%")
    merkle_genpk_test()
    print("66%")
    merkle_sign_test()
    print("ok")
