from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aesctr256(sk: bytes, counter: bytes, bytes_: int) -> bytes:
    size_of_buffer = 4096  # TODO static ?
    buffer = bytes.fromhex("00" * size_of_buffer)
    if bytes_ == 0:
        raise Exception("AES unimplemented: bytes_ was 0")
    out = b''
    cipher = Cipher(algorithms.AES256(sk), modes.CTR(counter))
    encryptor = cipher.encryptor()
    while bytes_ > size_of_buffer:
        out += encryptor.update(buffer[:min(bytes_, 4096)])
        bytes_ -= size_of_buffer

    if bytes_ > 0:
        out += encryptor.update(buffer[:bytes_])

    # TODO ADD FINAL ?
    # print("AES returned: " + out.hex())
    return out


def aesctr256_zeroiv(sk, bytes_):
    return aesctr256(sk, bytes.fromhex("00" * 16), bytes_)


if __name__ == "__main__":
    print(aesctr256(bytes.fromhex("00" * 32), bytes.fromhex("00" * 16), 16).hex())
    print(aesctr256(bytes.fromhex("0F" * 32), bytes.fromhex("01" * 16), 16).hex())
    print(aesctr256_zeroiv(bytes.fromhex("FF" * 32), 16).hex())
    print(aesctr256(bytes.fromhex("00" * 32), bytes.fromhex("00" * 16), 2144).hex())

    '''
    dc95c078a2408989ad48a21492842087
    16da6f2995c1848346af60eab5a45a5c
    4bf85f1b5d54adbc307b0a048389adcb
    dc95c078a2408989ad48a21492842087530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d18726003ca37a62a74d1a2f58e7506358edd4ab1284d4ae17b41e85924470c36f74741cbe181bb7f30617c1de3ab0c3a1fd0c48f7321a82d376095ace0419167a0bcaf49b0c0cea62de6bc1c66545e1dadabfa77cd6e85da245fb0bdc5e52cfc29ba0ae1ab2837e0f36387b70e931760124362c2bb66d8f4b137fce8342c9cd386a1144296e27268a8e50df537a805d579bb21ebbdf357ed34bf58b5837150ddcaf362225e620a6070ac5ef529fb522466768b78c04b54e51ef5fa07e506a35fc6b0b710249c8626e1a96ad57828d7be2e1490a05a7cee43bde98b56e309dc01264ed6df6e82c1bfc72a59ad53a9c0e4347d6c5278507940a7def6ba93e8b6af1e46537276611bc766955c587d301ba847acc9dda78a438e2c0a69d514744c72d34f326b9b7ef34286ca0ef8a7eae06ebe669c537212402dcb5feae99d76c7f4a76abdb79c0dfaa038a0e2282c730ed48b869dac2f168ecf3ea610e61fac512c8e95fb8c06de62bc76695551358adb864cc268f914b49ab3aa20edfdb2d172798137b4b3d8ddd17522eb2cbfe4dc47cf9fb0fa1ccd23dedb5693d1f50ae4eddee70820b0f7c6e073089e2d1dfd97b06c32a50036d8284dbf3468292ee0b62ec87c887cb1eb76b46720104130dbf1966387482dc43f2388ef25d24144e144bd834e448e7da3bfa6eaf9bcda215cba500cf3b95cb432d195129fc3945f87d1862ca4d6ea8ff1201034dc4d328ff5fd73a9096234d379e4cfbf9c36f6589a8a2ce98a5fe4d97103bc15c5c4021d3396c1932b375036141acaf69d3f03b779c9e61a031f52d7ea9c6ddd5c862218ce87e7a11a1905757afce00a5349f44f29cbcc70b5b9feea555242cee83ce56b8580b81672c6beecccbca0ad562396cee878547f40eb08089be6a56751781e7e461e2cf8563bc13591494a4202d20494d7ad87459a757555b642284cc11f478507f5c95dff35ff8dd7ce4757edae11f88cde1b5048c20e6699a26b0695cd1679b45a22646f961d1131125c68d99313e32e4aa85724a1dc7ec1cffa29fe729683821ca8eef3bf3b1c2839c2fb6ced76493ffa22a62e789b1c2a96e0cb53fdeceeeb8dc7e1c65c75bf3d52218333906de4d67dc64422e5590ff4ac02ec30e4a9ac6759cab2e94a21d2f38f616e57a3b54ee802730aaa2f3c634d7117fc6c01ac6f055a9ed20c958c4e2ac2b699f00c7c14b302bd964195ad56fc9c722f607da1af9123e0dbcb0e93e12b64b2791d440d2476d88ea8dd4665a6587446c4189877a7745626407e7f63bd4632d2dbd8bc790f4a772b72396f8b2826677ff6090dc82c11a3ffe3542eac53a696139e098afd0dbc2a4d423756a368c7a34325e4adce918732e8ea7e60aba678a506608d0845966d29b5f79018ac1b5e94beb86888385bfd1e326a603964f7fa687a29b66eb3af8babfd7a3a8c90de10d9065e0fe04f1bf0d33bac2ee6854838098a48c4f7a1ff89ce5796031f8cd0dd0696c3614b1649cb1396040862f2fef11a1a02f0380cc700ba8a24327f0ca631bfe69aa8a93952fdd05c4f173682d75810fac9a9108e1dd5af6ed490801339607bf03fcc0601d499ecfb321004e0bb69ad96005ab3a7bee6b1bbc577a5744301b68564fafe5e0162145b3e5e5f36d3c01be52e349212a218ae657d3c6c02b94cb10bfdbad581546190fae5bf6ddbb5c20752b73cba732ff3fad438f5e578b3bc4f7d873365a353c234251654c8766cac745bf8859b1f0e77060555496cf09396e34eace52eab98dbed1470fcf8c839c98de5263f159ebcd224443c172f13e1ed6d3423f1d7174a2f314b71581e9c9d5ac7a321638dc9d3d9040c90a8e15dcae62879e109e9e560689444cf1e4f699dc86fe145fcaf144431add208a84991351291ea2389eed6eb15a5ebac75e8a367e08d124563342d0d4e0232cdc5730d6cfc833303319478501fbce922e987777678b4be6392ac4eb09a02a42af13e873183327016eee3bc5604aed1d9c08f25bd9562839c4fc54c77326b21fe314e9d2f29112a3c6b321ca2b027e0abf8803046e1ea2c36cdf468ea37de79e9840428f1662a38358aaf406fc8b29d5d6c617856743c84f91db2f9fee90e2fa6240ca0374514be97fcefcdd79f1e8d5b024ae4c61ea6f21decc90dde21c90c7e28a498e339fa4437c954219caa384c7768daaf87a548020276a8d4480397a7fbd7276e3004b7bad02e533571a5185d1b3527f6a6308be2d3cfa797742d1422269f3b706688429b704d39cce7c9d00b0b8ea0fdcfcbdc7f76aee3f0eb4c38c5cadc407d1e509dc2084bc4a45672f6a6566c9ca8619d3e2d561cb9f4ea248e5d3a3045898d195d2d95122738a94aa0d8a3d7cd60393ec64d7632a48a9e488afd5e43083ce4b95720f78042355e56fcfe3e1ea0063f4491be7a1b13b301af6b7b7c1a3433b87405f4473c6d155797500817983085fc3fa8700a489f9e3337bbc63bc50ea64891ef12bb5d9e88f8e13bcbc7af06a85d1eb703aa1869fe3f30b44dc136823d741e6fff976e303e52e3bb1eb88e184fd01fd42b06a12b3de5d27bb8c161bb789047f8561ec882ac9c89b1174d1586dcb2756e8d9216ae1d871783e6dbab03841a05ffd8ea739963434eb1537f87f779d80e566f150a90d353c5953260919c2a98892a292a649c427c17096ec0c7e9925b67c351852cc42bdd9284dd16e4d289c215e0ca50010c35962784a7fabd0e0d0beea3e2f936da826e43372863086b61160db2ec2ff36fb1469533f8b6dd5dcd4e4fe5f5f9ecaed291084232bdc0cac87823c4ed0ded6ffe92afe6a56ffdb14dad8d3d9153f46c0d3a1ad63c7a05b81a0bc699a3039d192ffb012ac1b94ab0a65d63d3df2ce6a21fe7cfdbb867d18f5990a526d183c74a8d70b6bfecb0b213893f5db036490a9e839b07aac73afdb3765fb5a9190632a1abe08581c5f0e5
    '''
