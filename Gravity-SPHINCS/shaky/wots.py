from finished.hash import hash_N_to_N_chain, Hash, Address
from common import WOTS_ell, HASH_SIZE
from finished.aes import aesctr256
from utils.hash_utlis import hash_to_bytes, list_of_hashes_to_bytes
from utils.bytes_utils import int_list_to_bytes


class Wots_SK:
    def __init__(self):
        self.k = [Hash() for _ in range(WOTS_ell)]


def wots_chain(src: Hash, count: int):
    dst = hash_N_to_N_chain(src, count)


def wots_gensk(key: Hash, address: Address, sk: Wots_SK):
    iv = [None for _ in range(16)]

    iv[0] = (address.index >> 56) & 0xFF
    iv[1] = (address.index >> 48) & 0xFF
    iv[2] = (address.index >> 40) & 0xFF
    iv[3] = (address.index >> 32) & 0xFF
    iv[4] = (address.index >> 24) & 0xFF
    iv[5] = (address.index >> 16) & 0xFF
    iv[6] = (address.index >> 8) & 0xFF
    iv[7] = address.index & 0xFF

    iv[8] = (address.layer >> 24) & 0xFF
    iv[9] = (address.layer >> 16) & 0xFF
    iv[10] = (address.layer >> 8) & 0xFF
    iv[11] = address.layer & 0xFF

    iv[12] = 0
    iv[13] = 0
    iv[14] = 0
    iv[15] = 0

    out = aesctr256(hash_to_bytes(key), int_list_to_bytes(iv), WOTS_ell * HASH_SIZE)
    # out is now as bytes, need to convert to wots sk
    for i in range(WOTS_ell):
        for j in range(HASH_SIZE):
            sk.k[i].h[j] = out[i * HASH_SIZE + j]


if __name__ == "__main__":
    h = Hash()
    for i in range(32):
        h.h[i] = i
    a = Address(1, 2)
    w = Wots_SK()
    wots_gensk(h, a, w)
    print(list_of_hashes_to_bytes(w.k).hex())

    """
    148161be7b61a6c76fef7eaebd34142848cdb7f940d68f99df3b95bd671906993aba23d3bcb33d507115a9072bf6735320ed77bf144667c9d2c91c4234124fe528c151c09925de6ca302b410a10566594f10cd6c139e6d8ff25b53ad5f83b7db3559c526c93c5f0655374ee204c47e14be7453d54736d537a7b6a88f51e9748f7ca4e977fc1c754991de6081120aeee425c7fadd9bee8974fb4aa4e9c893a636756d11f42d4254ca4e0e62998d286a40e7e25efa74b57ae52f225416d563601bea1fb85a31434e9b2cdfae92b108409627383ba5729e707c57d74ffacb6108bed20e663811680b02160d34ee4b82178104bb55b3d02e6ced5d6f2913b61966867bf83fe2f858e118a9c9b7f7b95c6501e75b7392ea36c8f2dd92eb1bd7e928170ff9366c0c8cda29207a823d95e5af6e6a745b0d807bdb9ee6e42f932d4089ac63d892fbc5739cfe54117504f2a6f3bd019e7431fce2ed67d64f28958891c822a4413ee2e8e4f5b0d104e2363a6e2655811b9b4ddc24d9e9c0e6c50036dc2ef6842a3b8a4611e799d5acca38f6d76658ea730a9be67075229cc4c415205d10958df6f8daf12472ef1ba8d877d510cefa1b8a6d82f726e797f6319627bd0899ca6a201a7f3530da320f2544c14c5818d021b946918f3c331037508ad16c4d5e527dd32daf525cf56f52f86fc9e7cd04b565560e78beafcea64abadaadb41015dda435fbdc3c0ded6a5de0c67ddc397345a3881605beb21a35011801f624ffcf412b29f7c528bbeab49297c09c71e32a54efced94c18fc131bccba274e618d7af57becc076db416931158b88508d8dee46c9e828cf70ec5bd31c5d83f0189f7c9c9892b7d46eedcfeaaf01bd00e80317603a27ed1a76ff15a4f37e72ffa7f8eae1cf4df5b7c22fc605f561bd45c168aacddacac2714754064e4c9acc47500eb07fa635becc7812ee7c548f478e06396efd031a85e6c382a5523ab7a900ba1f960597d256903f434fe98f4e012b7544d9318ed3fa5b2bdd42e16737ed53cc4d423965aac97876f8fc281ca8f404d5ee3aa2ebc47760514a47d4a6b39c70fbdf82b6ba0da97c6ecb4de0910c0c5925eec5d50df582e8dca52f7aadeabe7d16abab19b482d192427c871dc453ac5e5f5d912827379601ebfaae237d94043cf939529dc9d9f21edf396b4c9022dd2fc0cca177c7b055143a53dd172625d3c1e2c3993ca2d5cac882dffff5fd3798291ffe69c000f677f054074ef220f5ed4f3974e24afe91a4c8e9197a6010e5c6e39a1b23ebf94ab077a08f40ff46bc3aa39cea851abb91c463a9959485421b4aec43f1c15f5d6ba7b4e4c38cb00bc5258aacc1f3f12f0b2eb20276b6ef0d63a796f0e6bb4cc3fcb23c503ecd95ebac0082fa40886350319aa50ab18a67f588f5befbd941dc4568191d28007ba0600596a13639565bd768dfd54a92175f55ac9826ae7696cd7df27172c35f6307023aed5e6fd7b01c36f5a23de7433dda9ea2df247152c69cd916fabaae7ff81eb5cd0a8cd2f8a534b3345d777dc0f3c0fd22f7fc383414346aff351d6385447d998fe48620e5fc0c059d25c32bf9753c45a0478e20bcb2569b20c7c5f44384a460cdc2f88142ba75587195f6b47d507718fc6397afa19c0cd61dc50b717f8ee13db222584735c8f84f2d226d43ea04ea49ff320f496e09cb0aa47f2bba882ef7bf8eedec9bd9a9d7dde511ba9697014b23e9596c269289b080d63e980e61263ad28c2bc49f7751c37ac69153ee4e3575830df901d807e748ecc96785db2d0940f14345bd5fa7e34e88cc3f50bf65b35d4423e3fb82d246cd129bf9b596d04331726b233de44846f8c344b34220358b53dc5f515cc001b86b06016d1e7c5da162e3ec4deb8c667095af513354c11800dc34438419c7c5ec3cd386c91d3d0d2dd7bd59ba6561ac1d1d4766271883fc66ed1537a59c828e53e56ddeddb4d54316d5001b6546cc2135115793011886adabbd1cd611052991dc44da63a672ccc1c2919f5ea6f8f12d25aeb643c15d71a2459653d617ba926f938a6c3e3a18f5ff3227aa78ae783f18b36ce75b44364c58719d46c505dc7ba5f72ba766a4b6b4d768fabf697affdd2495faa9f2e1eab722f8acb099da77e25a8976409c7a66b407a6559e3ff69174bbf2ff70cf94bc2d70c0e577598e04c642b7d3fb67e3b90f3bb9dc1b2ae28583579b80de17efef28895da57b811b084f7f3953501564cfcaea8e82dfa56f27a93faec632a13b79bef73d03e16c626819b7ab8e771bc505544102bc49acf5bd7561fdd0e3ba2f212cfae95717e63f65b40e72710659a7c01896b871b620209a9ed285b0f1c022179f46e2206d7264f22ae656488546296fe7efcafdd65ce9587529b8de6351e479cb82d6c1771727470317a5b79bbab1161755b92ea84c10adcc6f2c29cd78f36c98fd51f487b3111adcf96c61dcdf87c09774ccd96ec0fb77254b9c6dd2943b34ef39a0df60114b58eb59d87e480ceb368c399055f35a5a0997758b32490cc4b160f233b6cbcc74e5749d5f1191650f121d159b2813ab55b2738e455769b4027fe0079358769e3351fb9fee3a2120818dbea387d47118eb08379987a1a7b7cab4c164b339a79c0531186641830a9a7638e00e1865abde7a46f047917ee5af159ab224ba53ea8795c7d99dac87ff85414bf9d06aa48b10a58a8360009434da9a99d3428ce7153d4821297f852aff3ba30c141eb9acb41d3bda4b504e160b3b94835b2ef3fa3424d89d30e84f61765850af332a56293b95ce9a4671b3b2c24908b6519cb1a1d34fcc12427c5052daf02d9d00302bda9920ef3b867584cc523be0d50d61b7a8fb4f56b667f8abb11a316f4977f5fc9b07d4d9a3cb1cfeab4c7926f5043907e0290af0495e18f68cccef3e2953bf7beda950c9ca669dac27cfdd56961e46b6fbbf823ecd3d833b8963bb5dd1ac3038eda77da0f7d08878e4b9c065471f55a04dc263977878b23d25adb024d193c9134ba400d4332795c60f
    """