import itertools
import copy

MPAR = 1
ROUNDS = 5 + 1
AES_ROUNDS = 2

# AES S-box
S = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
     [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
     [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
     [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
     [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
     [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
     [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
     [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
     [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
     [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
     [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
     [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
     [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
     [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
     [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
     [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]


RC = [0x0684704ce620c00ab2c5fef075817b9d, 0x8b66b4e188f3a06b640f6ba42f08f717,
      0x3402de2d53f28498cf029d609f029114, 0x0ed6eae62e7b4f08bbf3bcaffd5b4f79,
      0xcbcfb0cb4872448b79eecd1cbe397044, 0x7eeacdee6e9032b78d5335ed2b8a057b,
      0x67c28f435e2e7cd0e2412761da4fef1b, 0x2924d9b0afcacc07675ffde21fc70b3b,
      0xab4d63f1e6867fe9ecdb8fcab9d465ee, 0x1c30bf84d4b7cd645b2a404fad037e33,
      0xb2cc0bb9941723bf69028b2e8df69800, 0xfa0478a6de6f55724aaa9ec85c9d2d8a,
      0xdfb49f2b6b772a120efa4f2e29129fd4, 0x1ea10344f449a23632d611aebb6a12ee,
      0xaf0449884b0500845f9600c99ca8eca6, 0x21025ed89d199c4f78a2c7e327e593ec,
      0xbf3aaaf8a759c9b7b9282ecd82d40173, 0x6260700d6186b01737f2efd910307d6b,
      0x5aca45c22130044381c29153f6fc9ac6, 0x9223973c226b68bb2caf92e836d1943a,
      0xd3bf9238225886eb6cbab958e51071b4, 0xdb863ce5aef0c677933dfddd24e1128d,
      0xbb606268ffeba09c83e48de3cb2212b1, 0x734bd3dce2e4d19c2db91a4ec72bf77d,
      0x43bb47c361301b434b1415c42cb3924e, 0xdba775a8e707eff603b231dd16eb6899,
      0x6df3614b3c7559778e5e23027eca472c, 0xcda75a17d6de7d776d1be5b9b88617f9,
      0xec6b43f06ba8e9aa9d6c069da946ee5d, 0xcb1e6950f957332ba25311593bf327c1,
      0x2cee0c7500da619ce4ed0353600ed0d9, 0xf0b1a5a196e90cab80bbbabc63a4a350,
      0xae3db1025e962988ab0dde30938dca39, 0x17bb8f38d554a40b8814f3a82e75b442,
      0x34bb8a5b5f427fd7aeb6b779360a16f6, 0x26f65241cbe5543843ce5918ffbaafde,
      0x4ce99a54b9f3026aa2ca9cf7839ec978, 0xae51a51a1bdff7be40c06e2822901235,
      0xa0c1613cba7ed22bc173bc0f48a659cf, 0x756acc03022882884ad6bdfde9c59da1,
      # bonus from sphincs
      0x2ff372380de7d31e367e4778848f2ad2, 0x08d95c6acf74be8bee36b135b73bd58f,
      0x5880f434c9d6ee9866ae1838a3743e4a, 0x593023f0aefabd99d0fdf4c79a9369bd,
      0x329ae3d1eb606e6fa5cc637b6f1ecb2a, 0xe00207eb49e01594a4dc93d6cb7594ab,
      0x1caa0c4ff751c880942366a665208ef8, 0x02f7f57fdb2dc1ddbd03239fe3e67e4a]


# get padded hex for single byte
def hexbyte(x):
    return hex(x)[2:].zfill(2)


# print list of bytes in hex
def ps(s):
    return " ".join([hexbyte(x) for x in s])

# multiply by 2 over GF(2^128)
def xtime(x):
    if (x >> 7):
        return ((x << 1) ^ 0x1b) & 0xff
    else:
        return (x << 1) & 0xff


# xor two lists element-wise
def xor(x, y):
    return [x[i] ^ y[i] for i in range(16)]


# apply a single S-box
def sbox(x):
    return S[(x >> 4)][x & 0xF]


# AES SubBytes
def subbytes(s):
    return [sbox(x) for x in s]


# AES ShiftRows
def shiftrows(s):
    return [s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11]]


# AES MixColumns
def mixcolumns(s):
    return list(itertools.chain(*
                                [[xtime(s[4 * i]) ^ xtime(s[4 * i + 1]) ^ s[4 * i + 1] ^ s[4 * i + 2] ^ s[4 * i + 3],
                                  s[4 * i] ^ xtime(s[4 * i + 1]) ^ xtime(s[4 * i + 2]) ^ s[4 * i + 2] ^ s[4 * i + 3],
                                  s[4 * i] ^ s[4 * i + 1] ^ xtime(s[4 * i + 2]) ^ xtime(s[4 * i + 3]) ^ s[4 * i + 3],
                                  xtime(s[4 * i]) ^ s[4 * i] ^ s[4 * i + 1] ^ s[4 * i + 2] ^ xtime(s[4 * i + 3])]
                                 for i in range(4)]))


# AES single regular round
def aesenc(s, rk):
    s = subbytes(s)
    s = shiftrows(s)
    s = mixcolumns(s)
    s = xor(s, rk[::-1])
    return s


# consider 4 consecutive entries as 32-bit values and shift each of them to the left
def shift32(x):
    # make list of 32-bit elements
    w = [((x[i] << 24) ^ (x[i + 1] << 16) ^ (x[i + 2] << 8) ^ x[i + 3]) << 1 for i in [0, 4, 8, 12]]
    return list(itertools.chain(*[[(q >> 24) & 0xFF, (q >> 16) & 0xFF, (q >> 8) & 0xFF, (q >> 0) & 0xFF] for q in w]))


# linear mixing for Haraka-512/256
def mix512(s):
    return [s[0][12:16] + s[2][12:16] + s[1][12:16] + s[3][12:16],
            s[2][0:4] + s[0][0:4] + s[3][0:4] + s[1][0:4],
            s[2][4:8] + s[0][4:8] + s[3][4:8] + s[1][4:8],
            s[0][8:12] + s[2][8:12] + s[1][8:12] + s[3][8:12]]


# linear mixing for Haraka-256/256
def mix256(s):
    return [s[0][0:4] + s[1][0:4] + s[0][4:8] + s[1][4:8],
            s[0][8:12] + s[1][8:12] + s[0][12:16] + s[1][12:16]]


# convert RC to 16 words state
def convRC(rc):
    rcstr = hex(rc)[2:].zfill(32)

    return [int(rcstr[i:i + 2], 16) for i in range(0, 32, 2)]


# Haraka-512/256
def haraka512_256(msg):

    # obtain state from msg input and set initial rcon
    s = [msg[i:i + 16] for i in [0, 16, 32, 48]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]

    # apply round functions
    for t in range(ROUNDS):
        # first we do AES_ROUNDS of AES rounds and update the round constant each time
        for m in range(AES_ROUNDS): 
            s = [aesenc(s[i], convRC(RC[4 * t * AES_ROUNDS + 4 * m + i])) for i in range(4)]

        # now apply mixing
        s = mix512(s)

    # apply feed-forward
    s = [xor(s[i], msg[16 * i:16 * (i + 1)]) for i in range(4)]

    # truncation
    return s[0][8:] + s[1][8:] + s[2][0:8] + s[3][0:8]


# Haraka-256/256
def haraka256_256(msg):
    # obtain state from msg input and set initial rcon
    s = [msg[i:i + 16] for i in [0, 16]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]


    # apply round functions
    for t in range(ROUNDS):
        # first we do AES_ROUNDS of AES rounds and update the round constant each time
        for m in range(AES_ROUNDS):
            s = [aesenc(s[i], convRC(RC[2 * t * AES_ROUNDS + 2 * m + i])) for i in range(2)]
            rcon = shift32(rcon)

        # now apply mixing
        s = mix256(s)

    # apply feed-forward
    s = [xor(s[i], msg[16 * i:16 * (i + 1)]) for i in range(2)]

    # truncation
    return list(itertools.chain(*s))


def haraka256_256_chain(msg, chainlen):

    s = [msg[i:i + 16] for i in [0, 16]]
    t_ = [msg[i:i + 16] for i in [0, 16]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]
    for c in range(chainlen):
        for t in range(ROUNDS):
            for m in range(AES_ROUNDS):
                s = [aesenc(s[i], convRC(RC[2 * t * AES_ROUNDS + 2 * m + i])) for i in range(2)]
                rcon = shift32(rcon)

            s = mix256(s)
        for i in range(16):
            s[0][i] = t_[0][i] = s[0][i] ^ t_[0][i]
            s[1][i] = t_[1][i] = s[1][i] ^ t_[1][i]

    return s[0] + s[1]

'''
Na wejściu dostaje listę bajtów jako inty np [0xAA, 0xBB...]
'''
if __name__ == "__main__":
    #print(ps(haraka512_256([1 for i in range(32)] + [2 for i in range(32)])))
    def ps(s):
        return " ".join([hexbyte(x) for x in s])

    def hexbyte(x):
        return hex(x)[2:].zfill(2)
  
    #print(ps(haraka256_256([i for i in range(64)])))
    #print(ps(haraka512_256([i for i in range(64)]))) may be wrong!
    #print(ps(haraka256_256_chain([i for i in range(64)], 5)))

    '''
    dd 90 04 5b 92 99 32 74 ff f8 cc f4 69 03 d1 c8 18 4b 40 4c c8 37 35 55 1c 80 a7 2b 5f b3 20 45
    0e 27 51 4e 8a b7 b4 ee 15 3c 9a 54 13 fb 1e 98 4a 91 4f 5b 6f ea 17 22 85 41 ce 17 07 fc 4e 64
    ae 13 7b 6f 07 3c a8 60 2d 6c a2 06 6a 64 b4 5f 8f e9 76 be a2 ee b5 ce 1c 2e eb aa f7 00 46 36
    '''
