from finished.hash import hash_N_to_N_chain, Hash, Address, hash_parallel_chains
from shaky.common import WOTS_ell, HASH_SIZE, WOTS_ell1, WOTS_w
from finished.aes import aesctr256
from finished.ltree import ltree
from utils.hash_utlis import list_of_hashes_to_bytes
from utils.bytes_utils import int_list_to_bytes
from utils.key_utils import gensk


# TODO some redundancy here
class WotsSK:
    def __init__(self):
        self.k = [Hash() for _ in range(WOTS_ell)]


class WotsPK:
    def __init__(self):
        self.k = [Hash() for _ in range(WOTS_ell)]


class LwotsPK:
    def __init__(self):
        self.k = Hash()


class WotsSign:
    def __init__(self, src=None):
        if src:
            self.s = [Hash(src[i * HASH_SIZE: (i+1) * HASH_SIZE]) for i in range(WOTS_ell)]
        else:
            self.s = [Hash() for _ in range(WOTS_ell)]

    def __eq__(self, other):
        if isinstance(other, WotsSign):
            for i in range(len(WOTS_ell)):
                if self.s[i] != other.s[i]:
                    return False
            return True
        return False

    def __repr__(self):
        return f'WOTS SIGN: {{ s: {self.s}}}'

    @staticmethod
    def size():
        return HASH_SIZE * WOTS_ell

# HAS TRANSITIVE TEST
def wots_chain(src: Hash, count: int) -> Hash:
    return hash_N_to_N_chain(src, count)


#  TESTED
def wots_gensk(key: Hash, address: Address, sk: WotsSK):
    gensk(key, address, sk, WOTS_ell)


# TESTED
def wots_sign(sk: WotsSK, sign: WotsSign, msg: Hash):
    checksum = 0

    for i in range(0, WOTS_ell1, 2):
        v = msg.h[i // 2]
        a = (v >> 4) & 15
        b = v & 15
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)

        sign.s[i] = wots_chain(sk.k[i], a)
        sign.s[i + 1] = wots_chain(sk.k[i + 1], b)

    # Checksum values
    for i in range(WOTS_ell1, WOTS_ell):
        sign.s[i] = wots_chain(sk.k[i], checksum & 15)
        checksum >>= 4


# WOTS with L-tree and without masks */
# TESTED
def lwots_ltree(pk: WotsPK, root: LwotsPK):
    root.k = ltree(pk.k[:2 * WOTS_ell])


# TESTED
def lwots_genpk(sk: WotsSK, pk: LwotsPK):
    tmp = WotsPK()

    tmp.k = hash_parallel_chains(sk.k, WOTS_w - 1)
    lwots_ltree(tmp, pk)


# TESTED
def lwots_extract(pk: LwotsPK, sign: WotsSign, msg: Hash):
    tmp = WotsPK()

    checksum = 0
    for i in range(0, WOTS_ell1, 2):
        v = msg.h[i // 2]
        a = (v >> 4) & 15
        b = v & 15
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)
        tmp.k[i] = wots_chain(sign.s[i], WOTS_w - 1 - a)
        tmp.k[i + 1] = wots_chain(sign.s[i + 1], WOTS_w - 1 - b)

    # Checksum values
    for i in range(WOTS_ell1, WOTS_ell):
        tmp.k[i] = wots_chain(sign.s[i], WOTS_w - 1 - (checksum & 15))
        checksum >>= 4

    lwots_ltree(tmp, pk)


# TEST UTIL
def sample_wots_gensk():
    h = Hash()
    for i in range(32):
        h.h[i] = i
    a = Address(1, 2)
    w = WotsSK()
    wots_gensk(h, a, w)
    return w


def wots_gensk_test():
    w = sample_wots_gensk()
    expected = "148161be7b61a6c76fef7eaebd34142848cdb7f940d68f99df3b95bd671906993aba23d3bcb33d507115a9072bf6735320ed77bf144667c9d2c91c4234124fe528c151c09925de6ca302b410a10566594f10cd6c139e6d8ff25b53ad5f83b7db3559c526c93c5f0655374ee204c47e14be7453d54736d537a7b6a88f51e9748f7ca4e977fc1c754991de6081120aeee425c7fadd9bee8974fb4aa4e9c893a636756d11f42d4254ca4e0e62998d286a40e7e25efa74b57ae52f225416d563601bea1fb85a31434e9b2cdfae92b108409627383ba5729e707c57d74ffacb6108bed20e663811680b02160d34ee4b82178104bb55b3d02e6ced5d6f2913b61966867bf83fe2f858e118a9c9b7f7b95c6501e75b7392ea36c8f2dd92eb1bd7e928170ff9366c0c8cda29207a823d95e5af6e6a745b0d807bdb9ee6e42f932d4089ac63d892fbc5739cfe54117504f2a6f3bd019e7431fce2ed67d64f28958891c822a4413ee2e8e4f5b0d104e2363a6e2655811b9b4ddc24d9e9c0e6c50036dc2ef6842a3b8a4611e799d5acca38f6d76658ea730a9be67075229cc4c415205d10958df6f8daf12472ef1ba8d877d510cefa1b8a6d82f726e797f6319627bd0899ca6a201a7f3530da320f2544c14c5818d021b946918f3c331037508ad16c4d5e527dd32daf525cf56f52f86fc9e7cd04b565560e78beafcea64abadaadb41015dda435fbdc3c0ded6a5de0c67ddc397345a3881605beb21a35011801f624ffcf412b29f7c528bbeab49297c09c71e32a54efced94c18fc131bccba274e618d7af57becc076db416931158b88508d8dee46c9e828cf70ec5bd31c5d83f0189f7c9c9892b7d46eedcfeaaf01bd00e80317603a27ed1a76ff15a4f37e72ffa7f8eae1cf4df5b7c22fc605f561bd45c168aacddacac2714754064e4c9acc47500eb07fa635becc7812ee7c548f478e06396efd031a85e6c382a5523ab7a900ba1f960597d256903f434fe98f4e012b7544d9318ed3fa5b2bdd42e16737ed53cc4d423965aac97876f8fc281ca8f404d5ee3aa2ebc47760514a47d4a6b39c70fbdf82b6ba0da97c6ecb4de0910c0c5925eec5d50df582e8dca52f7aadeabe7d16abab19b482d192427c871dc453ac5e5f5d912827379601ebfaae237d94043cf939529dc9d9f21edf396b4c9022dd2fc0cca177c7b055143a53dd172625d3c1e2c3993ca2d5cac882dffff5fd3798291ffe69c000f677f054074ef220f5ed4f3974e24afe91a4c8e9197a6010e5c6e39a1b23ebf94ab077a08f40ff46bc3aa39cea851abb91c463a9959485421b4aec43f1c15f5d6ba7b4e4c38cb00bc5258aacc1f3f12f0b2eb20276b6ef0d63a796f0e6bb4cc3fcb23c503ecd95ebac0082fa40886350319aa50ab18a67f588f5befbd941dc4568191d28007ba0600596a13639565bd768dfd54a92175f55ac9826ae7696cd7df27172c35f6307023aed5e6fd7b01c36f5a23de7433dda9ea2df247152c69cd916fabaae7ff81eb5cd0a8cd2f8a534b3345d777dc0f3c0fd22f7fc383414346aff351d6385447d998fe48620e5fc0c059d25c32bf9753c45a0478e20bcb2569b20c7c5f44384a460cdc2f88142ba75587195f6b47d507718fc6397afa19c0cd61dc50b717f8ee13db222584735c8f84f2d226d43ea04ea49ff320f496e09cb0aa47f2bba882ef7bf8eedec9bd9a9d7dde511ba9697014b23e9596c269289b080d63e980e61263ad28c2bc49f7751c37ac69153ee4e3575830df901d807e748ecc96785db2d0940f14345bd5fa7e34e88cc3f50bf65b35d4423e3fb82d246cd129bf9b596d04331726b233de44846f8c344b34220358b53dc5f515cc001b86b06016d1e7c5da162e3ec4deb8c667095af513354c11800dc34438419c7c5ec3cd386c91d3d0d2dd7bd59ba6561ac1d1d4766271883fc66ed1537a59c828e53e56ddeddb4d54316d5001b6546cc2135115793011886adabbd1cd611052991dc44da63a672ccc1c2919f5ea6f8f12d25aeb643c15d71a2459653d617ba926f938a6c3e3a18f5ff3227aa78ae783f18b36ce75b44364c58719d46c505dc7ba5f72ba766a4b6b4d768fabf697affdd2495faa9f2e1eab722f8acb099da77e25a8976409c7a66b407a6559e3ff69174bbf2ff70cf94bc2d70c0e577598e04c642b7d3fb67e3b90f3bb9dc1b2ae28583579b80de17efef28895da57b811b084f7f3953501564cfcaea8e82dfa56f27a93faec632a13b79bef73d03e16c626819b7ab8e771bc505544102bc49acf5bd7561fdd0e3ba2f212cfae95717e63f65b40e72710659a7c01896b871b620209a9ed285b0f1c022179f46e2206d7264f22ae656488546296fe7efcafdd65ce9587529b8de6351e479cb82d6c1771727470317a5b79bbab1161755b92ea84c10adcc6f2c29cd78f36c98fd51f487b3111adcf96c61dcdf87c09774ccd96ec0fb77254b9c6dd2943b34ef39a0df60114b58eb59d87e480ceb368c399055f35a5a0997758b32490cc4b160f233b6cbcc74e5749d5f1191650f121d159b2813ab55b2738e455769b4027fe0079358769e3351fb9fee3a2120818dbea387d47118eb08379987a1a7b7cab4c164b339a79c0531186641830a9a7638e00e1865abde7a46f047917ee5af159ab224ba53ea8795c7d99dac87ff85414bf9d06aa48b10a58a8360009434da9a99d3428ce7153d4821297f852aff3ba30c141eb9acb41d3bda4b504e160b3b94835b2ef3fa3424d89d30e84f61765850af332a56293b95ce9a4671b3b2c24908b6519cb1a1d34fcc12427c5052daf02d9d00302bda9920ef3b867584cc523be0d50d61b7a8fb4f56b667f8abb11a316f4977f5fc9b07d4d9a3cb1cfeab4c7926f5043907e0290af0495e18f68cccef3e2953bf7beda950c9ca669dac27cfdd56961e46b6fbbf823ecd3d833b8963bb5dd1ac3038eda77da0f7d08878e4b9c065471f55a04dc263977878b23d25adb024d193c9134ba400d4332795c60f"
    if list_of_hashes_to_bytes(w.k).hex() != expected:
        raise Exception("Test failed")
    return w


def sample_wots_sign():
    w = sample_wots_gensk()
    s = WotsSign()
    h = Hash()
    for i in range(32):
        h.h[i] = 1 + i
    wots_sign(w, s, h)
    return s


def wots_sign_test():
    s = sample_wots_sign()
    expected = "148161be7b61a6c76fef7eaebd34142848cdb7f940d68f99df3b95bd67190699a3916427e37f9f5488a46c8050b13623a707b0db05f5e559655713473df67b9228c151c09925de6ca302b410a10566594f10cd6c139e6d8ff25b53ad5f83b7dbb7df17f66518e95c7306cf8b811d672b6aa619b67c18265e11d40044d9a266d27ca4e977fc1c754991de6081120aeee425c7fadd9bee8974fb4aa4e9c893a636c4452607f140c31cd6a7441c6c7fbc2e03efaf1351ac19c1dc06782b315c7056ea1fb85a31434e9b2cdfae92b108409627383ba5729e707c57d74ffacb6108beb2aa29409bed4ab35b742875f7f89769bb131cd59776934c9f3c3344b20ad1e47bf83fe2f858e118a9c9b7f7b95c6501e75b7392ea36c8f2dd92eb1bd7e9281717fe5a118c34830fb252fa841a6c175ba0fe8a745f17c8a7d5098f2ad2ddb6d163d892fbc5739cfe54117504f2a6f3bd019e7431fce2ed67d64f28958891c8221364237e699374f6f04ee3e8006fa2150a71b914c6f635a75bd85a9deb13e5e0842a3b8a4611e799d5acca38f6d76658ea730a9be67075229cc4c415205d1095cbe7f8a1e82ca166175eac0453fe9c86f3c42b61b915356be26cd0c9b266365a6a201a7f3530da320f2544c14c5818d021b946918f3c331037508ad16c4d5e52cae5eae12a535fadf2b14d58a6737b45f1e45d69a9d3429df739da8a0c685dcaa435fbdc3c0ded6a5de0c67ddc397345a3881605beb21a35011801f624ffcf412fc7643e4af29567537a1a34c5fda4d3b925e98daa0c062c516d75209453c4c77becc076db416931158b88508d8dee46c9e828cf70ec5bd31c5d83f0189f7c9c4176a915277301f31324d9644504b822e5940da492beecafed0992c19b5c31ebcf4df5b7c22fc605f561bd45c168aacddacac2714754064e4c9acc47500eb07f9856bbc2ffc7c176ea44b135a78c750e9ddce26c10826d1d5e9572f0cf87e7be97d256903f434fe98f4e012b7544d9318ed3fa5b2bdd42e16737ed53cc4d4239353d8569cfe3a27efcdcdbe4c13c071a30ed0e020f36095010e8d20e366afefaba0da97c6ecb4de0910c0c5925eec5d50df582e8dca52f7aadeabe7d16abab19ffa497ac38cbaac4235032ac8ffa7530d2340a264209fb8dc6d321e87b2ce771c9d9f21edf396b4c9022dd2fc0cca177c7b055143a53dd172625d3c1e2c3993cb9674f4751e7b150d1d80b1b8a9504a82e4d2c69756ee15aa925ed58fb0ef7cbfe91a4c8e9197a6010e5c6e39a1b23ebf94ab077a08f40ff46bc3aa39cea851a7610a4cdcca64e038faad5296b671645229846aa55733de8885ba4a554ad62f7b6dda91b85badfa771abdc943b6ba952025a5a7e9034cd0df1f8df33df89b3a750319aa50ab18a67f588f5befbd941dc4568191d28007ba0600596a13639565b67aacfdc6e590aece4042e9cbb431408d5743fce08f0a13b01fcadfae0af939bc150ceb9227837ff2f8911fc3559261ae59f31bb170f990761bcfb8597e1bcc4f20df72000341fa3d4e440803b8dd3154e4ebf891b746f4a1a9188906c93018e819d2a61c3936e470932aeac933553cea77425b2c2f637b4ff1c58268309e3989265fa0d5c4bf37932ce34ad06aa4dc445ca1d96ca15fe963d7791883891aef84f46461af162c4fd5ddb1c72b4fd0afb8d015bfcae0ed46fe3c32871023855230e90bad445e22548b974f987806d806b4c6def7aef3a1f42b15ee4205f39c11b420b1dcef26a5695e058d6cea1eb5a2b8f72f48b68f7e4d9611f3ba552c3dcfe2149f82b9cb6f4bb70c6a3ee0fe2cf3cae969a8f0b94f1492f4be2247ad60d07beb2fb158efd981ab025067bcf7f3d1f5cb986cab694532bf6d2c66a5a2a2ca8c468b2eda5d8a8d840c7d63bcc56a156260ee5a9699e9daf45d239a28aeddb898a0b5a36f37e4ea376d0059199da2cd2b3335bfb58625895441ddfa9f7c4ae992123072a4998d98b15e81817f6648e3d1f05f17a524f35a1b78d83b294f8d524101955b844833ca575e69b7461f27ba6549c068b12d37f8965c7f21991c8231fe4b64762f21b92f07a6959b29f1f0866a8ec798fefae73e50d9d6ec4d957bb088ef169fff8ed5786b9fa87f0f0a049aa1c23035e1f2333923ea47d98afc78d5f46a6482b0acbeb7337e96f88b732b4b51412ce4c0607ffd63cf07b3383ffafc6c3280848a51205d4439577bfcbe6671384373ce2d4c346bc7e9af55767528a8e95d1f2f5be7d44a56143f6256ba367b286d8829eee2abbbbb2423885d0ff27ff39bfa08016e4273a5b7ebf93a15281b8d40a498946835e39812427f3b35de2184e0493eaab0a244f7809c228edd80549f6286d569298d2c9213e5deaf8589f9f4ecdda6cd9d6eb02cd0db8faf03fab70e3a7144a279ac666b8b42dec2924cee91dd0c87b8d49ebd07cc6abd04b638bcb24c3528481ae1d118d4c2ac1710b9c89b7c8aef8f2d27602af8558a36a01fd7b520b7e3400ac609b77c9b5e4ee90e0cf31f1cbf27c4e8082d2ebc9c653f7aeb50cd51d52a8846e2b7c46e636de6eb72c9f513a64610e0100a18fd7b2f4ef74ceb29529fb596cb8adefd6cc38339bb2543de6506428a13fb4a0d6e2509f5e4ad327a5bb4fff54b0e3f9d0ed45a109929dc2cf3bfa3233cf2c8f2a8ac6caa2a5c8fab48d6fa4dd74c0eb6956986862cfb53610152869689b37ff0c7037b021536518c19ea9839af15c6fb516277f1419d6b615826b00056d833ee9bd9f6f6a9db7a2c2a9c661322e62f77e87a5b210341660d2baf09a91dfc6a8d7dce22d330b44e9e893b9b3c1fd07473e19c38300cd00523be0d50d61b7a8fb4f56b667f8abb11a316f4977f5fc9b07d4d9a3cb1cfeab6671581b8961d2e4f3152c2e93c8cc01c773066d96ec3d6fb4d47ffa43274ab23fd5b00ae60783bd14e5240ae8bff1afc67afbf4bd18fcfe294f09cd6f03fb57270edb512cf9cdab36f06e602d9fb61cf0ab8e99e001496b0cd1f22f041fa7bd"
    if list_of_hashes_to_bytes(s.s).hex() != expected:
        raise Exception("Test failed")


def sample_lwots_genpk():
    w = sample_wots_gensk()
    p = LwotsPK()
    lwots_genpk(w, p)
    return p


def lwots_genpk_test():
    p = sample_lwots_genpk()
    expected = "3f44b236e974988ff0959beeb4b10d1dcf63112a1814bf222c7f3bdb095b08b7"
    if (p.k.to_bytes()).hex() != expected:
        raise Exception("Test failed")


def lwots_extract_test():
    h = Hash([8 + i for i in range(32)])
    s = sample_wots_sign()
    p = LwotsPK()
    lwots_extract(p, s, h)
    expected = "30774304e6020b3592764cf73f30d72daecb9ea544ba1e06a71167699c9d7e22"
    if p.k.to_bytes().hex() != expected:
        raise Exception("Test failed")


if __name__ == "__main__":
    lwots_extract_test()
    lwots_genpk_test()
    wots_sign_test()
    wots_gensk_test()
    print("OK")
