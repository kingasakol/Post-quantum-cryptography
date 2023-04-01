from finished.aes import aesctr256_zeroiv
from finished.hash import Hash, Address, hash_parallel, hash_2N_to_N
from shaky.common import PORS_t, PORS_k, HASH_SIZE, PORS_tau, GRAVITY_OK, GRAVITY_ERR_VERIF, GRAVITY_mask
from shaky.merkle import merkle_alloc_buf, merkle_compress_all, merkle_gen_octopus, merkle_compress_octopus
from utils.bytes_utils import bytes_to_int_list
from utils.hash_utlis import list_of_hashes_to_bytes
from utils.key_utils import gensk

BYTES_PER_INDEX = 4
STREAMLEN = 8 * PORS_k + HASH_SIZE


class PorsSubset:
    def __init__(self):
        self.s = [None for _ in range(PORS_k)]  # [int]


class PorsSK:
    def __init__(self):
        self.k = [Hash() for _ in range(PORS_t)]

    def __repr__(self):
        print(f'PORS SK: {{k: {self.k}}}')


class PorsPK:
    def __init__(self):
        self.k = [None for _ in range(PORS_t)]


class PorsKeyPair():
    def __init__(self):
        self.pors_sk = PorsSK()
        self.pors_pk = PorsPK()


class PorsSign:
    def __init__(self):
        self.s = [Hash() for _ in range(PORS_k)]

    # TODO untested
    def __eq__(self, other):
        if isinstance(other, PorsSign):
            for i in range(PORS_k):
                if self.s[i] != other.s[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return f'PORS SIGN: {{s:{self.s}}}'


class PorstPK:
    def __init__(self):
        self.k = Hash()


class PorstKeypair:
    def __init__(self):
        self.sk = PorsSK()
        self.pl = PorstPK()


# PORST with authentication octopus
class OctoporstSign:
    s = PorsSign()
    octopus = [Hash() for _ in range(PORS_k * PORS_tau)]
    octolen = None

    # TODO untested
    def __eq__(self, other):
        if isinstance(other, OctoporstSign):
            if self.octolen != other.octolen:
                return False
            for i in range(self.octolen):
                if self.octopus[i] != other.octopus[i]:
                    return False
            return self.s == other.s
        return False

    def __repr__(self):
        return f'OCTOPORST SIGN: {{s: {self.s}, octopus: {self.octopus}, octolen: {self.octolen}}}'


# TESTED
def pors_gensk(key: Hash, address: Address, sk: PorsSK):
    gensk(key, address, sk, PORS_t)


# TESTED BY GRAVITY SIGN
def pors_sign(sk: PorsSK, sign: PorsSign, subset: PorsSubset):
    for i in range(PORS_k):
        index = subset.s[i]
        sign.s[i].h = sk.k[index].h.copy()


# TODO UNTESTED
# TODO returns int
def porst_genpk(sk: PorsSK, pk: PorstPK) -> int:
    buf = merkle_alloc_buf(PORS_tau)
    hash_parallel(buf, sk.k, PORS_t)
    merkle_compress_all(buf, PORS_tau, pk.k)
    return GRAVITY_OK


# TODO UNTESTED
# authors use selection sort here but we don't have to
# TODO or do we? maybe it is ~o(n) here, leaving func in case we want to optimize it
def sort_subset(subset: PorsSubset):
    subset.s.sort()


# TESTED BY GRAVITY SIGN
def octoporst_sign(sk: PorsSK, sign: OctoporstSign, pk: PorstPK, subset: PorsSubset) -> int:
    sort_subset(subset)
    pors_sign(sk, sign.s, subset)
    buf = merkle_alloc_buf(PORS_tau)
    hash_parallel(buf, sk.k, PORS_t)
    sign.octolen = merkle_gen_octopus(buf, PORS_tau, sign.octopus, pk.k, subset.s, PORS_k)
    return GRAVITY_OK


# TODO UNTESTED
# TODO returns int
def octoporst_extract(pk: PorstPK, sign: OctoporstSign, subset: PorsSubset) -> int:
    tmp = [Hash() for _ in range(PORS_k)]
    sort_subset(subset)
    hash_parallel(tmp, sign.s.s, PORS_k)
    res = merkle_compress_octopus(tmp, PORS_tau, sign.octopus, sign.octolen, subset.s, PORS_k)
    if res != GRAVITY_OK:
        return res
    pk.k = tmp[0].h.copy()
    return GRAVITY_OK


# TODO UNTESTED
# TODO returns int
def octoporst_loadsign(sing: OctoporstSign, _sign: [int], _len: int) -> int:
    if _len < PORS_k * PORS_tau * HASH_SIZE:
        return GRAVITY_ERR_VERIF

    _len -= PORS_k * HASH_SIZE

    if _len % HASH_SIZE != 0:
        return GRAVITY_ERR_VERIF

    _len /= HASH_SIZE

    if _len > PORS_k * PORS_tau:
        return GRAVITY_ERR_VERIF

    for i in range(PORS_k):
        sing.s.s[i] = _sign[i * HASH_SIZE: (i + 1) * HASH_SIZE].copy()
    for i in range(_len):
        sing.s.s[i] = _sign[(PORS_k + i) * HASH_SIZE: (PORS_k + i + 1) * HASH_SIZE].copy()
    sing.octolen = _len
    return GRAVITY_OK


# TESTED
def pors_randsubset(rand: Hash, msg: Hash, address: Address, subset: PorsSubset):
    seed = hash_2N_to_N(rand, msg)
    rand_stream = aesctr256_zeroiv(seed.to_bytes(), STREAMLEN)
    addr = 0
    count = 0
    offset = 0
    for i in range(HASH_SIZE):
        byte = rand_stream[i]
        addr = (addr << 8) | byte
        addr &= GRAVITY_mask
    address.index = addr
    while count < PORS_k:
        # shaky shaky xd
        index = int.from_bytes(rand_stream[HASH_SIZE + offset: HASH_SIZE + offset + 32][:4], byteorder='big') % PORS_t
        offset += BYTES_PER_INDEX
        duplicate = False
        for i in range(count):
            if subset.s[i] == index:
                duplicate = True
                break
        if not duplicate:
            subset.s[count] = index
            count += 1


# -------------------------------------------- TEST UTILS

def sample_pors_gensk():
    h = Hash([i for i in range(32)])
    a = Address(1, 2)
    w = PorsSK()
    pors_gensk(h, a, w)
    return w


def pors_gensk_test():
    w = sample_pors_gensk()
    # we have millions of bytes here and even print with conversion is slooow so testing parts
    if w.k[0].to_bytes().hex() != "148161be7b61a6c76fef7eaebd34142848cdb7f940d68f99df3b95bd67190699":
        raise Exception("Test failed")
    if list_of_hashes_to_bytes(w.k[
                               32000:32100]).hex() != "b165ea0af167d703031f2cce11d651def84e34e6146925c852f82e9341992fad62d8ae0b154bbecdc60ad73338a98d942cece24688e1e76729c74619e64da0117edbb5bcf8d6ec8ea22a1a7233f6483a3646e6d705a59b295b469afa3ebf19872dc08ab650340464cf07fff2b0469ad7cd64fdda2f2552119710319c78d893132e892d3fbb77a984b562241d99795dc8765b72272bf5eeefd7519f90c0186836431764ed8545b1925966352d8f0ece7b8fb5e5a3c74f8cc919dae0bbf9878fc37e6198aff958035c67feb696fb7f8217b1c76817a4ea9e89220d3594b1ce73708780cc56e84de6fe2e5dd36ac11fe070f6379c7389a4aa810e5d4cea120a18247af6b233fc7d41b972cb126d5e58f1ea2536ea97cd81528021a3179201d45a106c3614aecb0ce03a6467849f1ba12b7705cff6b9d7876a005fcbdc16a56b9caedb310ce35e810855341f648cbccc9e09dc0fcf4fb5b615f65edf1a873271df2b9ba8096f214a3c1c3da3a7e138245c02314d648ebf6905939b4707c5672efa207ae6f0e541912f9804e77cc47198def10df4b80d2fc58a0811db53eccc9c8cfa9d671257eff609ee70495afbf1ba99e08635b97a913b6b220ad5ad0e654c76aef1ac653173ed472748e64706efb75b70966b70729b61b590c3f97c69c19bc8bc6d7a52d9d3c88b331cf90a7ca3c8ece1197918fb51f43f1c872bc64453117e249e3067a4633a73cd14428a0518bbd23a8327112124bff49b01375d212570f8ace2a19cdffaec77707973edb7ef28e980552b87056d297f1c88c8a92ef0090818963f9149b3af550263bce69872a35aa4dddac34697f5d3a11b56e16a89092ab72c432f890a185e6b0f75faa250aa1c900498ac2d0d1d6f8a5824f1807d0bb55ef6a93bfe583e9f13c4af6be2db3558b97ece595b4dde62de562e76ed00b8e49c7b8d661cf749ad7f573f2c4cf60591767fa8192cf0273f323b8250cd922f3142d8c648bd8b97dbf5b61f5a6d3b08696aa1441d14fa119c3e5799f31f1231ccf288893654679b5d201d57c9d91acf55823364b60a144334996032e564384dcaf636c6231ad7583a4b41a383f4822eb7e6365b415fcf313d27363d063fd4830a01342322867642f9456c341f50ea817fd81c81a1878bee7307c0f5020c1ff0c9cd20b36afe354b413fb684842c6db469add09cd0d4e4eb45a700b83e9e47326b1064c62540f12f53ee2f6a0c8d300de1b21cf065c4f72402373aa5f7223f279a8c055c4c17380ee743155f642b153a1fe06b762104f2b5b2daacb87843867955b905b1f862da78bce434c7c611ac42263dd04759c4cd3606ec43aa29f15af4381f2999c73441e8de56b37f0b0d59008ef57278e3e973d71f893978ad0c21d2e6f0291c5b554151c0c183b5de8bfebb64cc178b902794c3a78ec66c2e34ebe3297500b9ba3ffad2d045ae86815f6838b35347afc600ebff22c4134e41971875f95265b5a5aa66a589aca08d7ade3a02c2db884e1bb01879710a54d74587d1de80e6a8bbd2098b78972eb7a1df393479faf67170b94f787e92eef2917f80ef8fe1f9ff1ac787813ca62ddc6ac7dfe4a46fe9f8a701ce0b67860167da955a151110e8e86eb7f6609922b07bc66cb0d23f60add308f8029e77d53533cc4e9572880d5ea4a1039715a11758dec8be3c5715211977817969d991028294b58bb4b720203eb07b2706be5db71ee2d0751998fa887d1a6f56e63a490232523b4dd6214b882e852f3515247d61d314d3b3bff032552569b638d3b63ea3718fb406d3f789b8d55b78e49cae09b07144a0591d71197d7be52bae8b11bf85a27178f62b685ea5ff0e8f841e919bfaab1feba33b09e424ad56281f7f0457744949e5a6944b0b8520b02e6fbf1afda9fca4fba511ffcbb72257089c6f2e83d35782719e69985fff2d5f217fe8d0025cd73052dc94361d60bb303623fd25ad4dee7ca87025ae314113f555e5596beba873cd20de9ac4db21744e10b7af9b0f5465f8e00500138440c60fed8a6dd4d2752c688a48aaf885012d8b8a533de54de56e2cbb9210de6c0b5cf81f4a6b90d273644554a3b3c25cbc81899f8a3af9632787c66f4222617d8857efc2c9434e8295be3429be5fbf98ffde798881c39ae0c8ffdd637797fbdc7ed50fb28d2e337d19aa98929324d2aedf084d9fca8d9f8c5f54019c74c37389c48e7a994d2420244d7ef669f98522011c67d99ccf2036409604b606a83610fb56692cdf10d7aa73b12cf231dc12ecf2253b25a707b9e0621012ec76d411346e2d1387d59b1dde174a0dbb2c5827524096e1c6d9e9ee18de2d5ed6d694be456cdc59f7b1b12745ab1de616feb05b7ae419b8f3bf7ea1bf180c097aae8384f846724dfe7ac8fdf3750cb8e0ca2e42669db2a67f153cadc22ae6f957471b25ecabffe6805230c1d8de8ff4925b06b33f5adfab013b4aab4f9e8399251bca182b66b1e5095e76884513257db93696da2899b23e76d5039a36294617bdfdc0884a59ead090a7ea7148ac1bfaa10ea8aac2893ed03269dd10da3e91be847638407bd071466b085eec2857c99cf5332b133e5acae470c6d1dbc775f0d829b2ef04a55aa8526e11b4faf000d24ada74956daaff45c4cdd79438e328689b79e1eade620faad44d1ad227130395774adb24b18244426fee0f83a5d779c0b34dbffd9ad596949f19bca7dcf586fa21a172c177b095f8d31baa91288e4c9888eaa6a70004bc023d38fcc5678c5166ebee6a31a0565b52c318f677b07330b35ecfabe6847443769fa700f0c7adfeb3baf748c4e8aad466f415b524789bd03b9202c0827907668d87224504a8e0510f63d13fbf70c8cf8402a33816b51880d1bafec2ca0109361fc5a114b8ea2a2f6c36390bb26e4b07cee99d6f3e9fcd98905f081c9766b4c166e61fa7a099d5f7265639b9309f1bc52e4b19448ea86344740161a1906d808b97b74a69c9954db0c6a28c16d21ad65ead1c6b42c90f231128231afbe0afa98e4b06cf9796a7543c4dbf31c3063da2b200f310cfa1d3c9ad13052024c02d23fc6a6cef3b212998ad0458fdf01f4dde44bea424a98c3d882161151c9b1be3b36509e72522ffaac7531b157c6f0b482a91540295f3fafa1264011e4f9a614c409d83440a7bdf7639f4a307e7ed6d4922deae3c00dde56dc0a9ee0558324b4a9c8641a1817c54ae492fe68a1eddaa8389a5dbdbbaa27d4e060d1620a18dd50483501c6b52701ad7012f4e82d6cddd09114158efd7d784ef7689a429a190f5e470a8050df52ac5e5ce32cfed2661f176737000ac919731856085d51411c7e81771d8ef19e3f63e360b457513604804e0e2d8858dd7d9611f5b26759c8a897c423b024d6f7c5bb687987e83a72c11113254f8e9a187a58bf057b511290a9982d04b4a7770a21fea2d6cf1078655240ab2f888ef66e6080d6ff73b2d1ad7ef5245190b99d96396ffd7137da9920c1b2dbad82076998714a3d43f5b692284c52daf329157b184c9127c922117e405f1bef32f66e4ffac000aefa604a3de06c838941546ac4b1919b4ed3370d8156f045241ddef8a7a0a01a5743f82c60e4d05810c6a37ce0283df7001aab0919894601f962d6fec739291193fb573f38d04e885416e2a596133f372b8029d4b17f2628262fdba16f7e5b9a2c4269673319746de4c947bce3ed9ec5f0dc5c348c5daff2cada11d4df8dcda2b73a0bc60868e9a6d75fb476fa49706404453fb3ea4c7baab09e4c2e9d4f84d9fe971996c2173d232a50db9d0e6d86a37749957c7d8340e7f13dbd1e9ed89d8df52c425da390e0d0a0355b81c5bb6539025a7228afc903b65eea08c52d9b605111959b5e369b440877af37d0a8d34007f582a06cf800a4a46f554429bc05a9c5df58d7553475fdf41cb9de87bc34876cddbe01537c88db3e4bfa765a8d28438094b9fe52ec1baed1f9ec7d149ed35ccfc51cd9564d5e60a1a370306de1fc8604882a76bf8802ed4c7e8a371dec43ed73485c671c96ce9dbe2452ba790039c4cf775e052ae73589c62e1cd8a337c42ad8ca49d51a2c8fa8b2dfe846e423cc2474535e8b247605f3f2c576f0a86845b4c1e0cc4458d9dade2095882398c60e90245086dc3fb6519e235adf7279a2c5dece3e56fca3f8ca343ef4cb8c57c78e8c0652391c293d214c53241b619da43534de0e8de31756136aabeace2ef54f59c7e9b3a15abfac43cb86c06d28c94c9b137520a477db2c6c0c8fca8eddfea71ff0bb7c079de59cfc639234fbe3940c5ce0354c6674da4a72fa2d7ad637b68a2efa7cb6d88136408d13ccaa8fdc3b6f880107b54a3d66792b1f8b2194ae2d5bce2a2e44d90f070dc954bdbe490024fac0a8504a1f2697450380752e6fa4bc5ccf387b57a4e69d61213417906e74f3acf59d61cd801b524d08e22cc6602125b895ff0969ba8bdc5f086f32b261072ffb2c63d1c85cda617164abcbf97a26103a0fd5540f027954836ad87eac56adf10c7":
        raise Exception("Test failed")
    if w.k[-1].to_bytes().hex() != "dc66f958853c0145a6fa96a72877a54429f5fc1530ab42ce792c8a2d81c20890":
        raise Exception("Test failed")
    return w


def pors_randsubset_test():
    rand = Hash(bytes_to_int_list(bytes.fromhex("116ec7ec0055b52f72310cdda417263458a58979c93dbc3c622cbdd424045c3f")))
    msg = Hash(bytes_to_int_list(bytes.fromhex("00020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e")))
    adr = Address(None, 10)
    res = PorsSubset()
    pors_randsubset(rand, msg, adr, res)
    if res.s != [50092, 52, 21074, 47954, 43329, 31136, 978, 61975, 7743, 64745, 14179, 1479, 17219, 25654, 55747,
                 58372, 46594, 10874, 55379, 47168, 50223, 19753, 45369, 39452, 60707, 51198, 18986, 7546]:
        raise Exception("Test failed")


if __name__ == "__main__":
    pors_gensk_test()
    pors_randsubset_test()
    print("ok")
