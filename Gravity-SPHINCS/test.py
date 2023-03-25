from haraka import haraka256_256, haraka512_256

def ps(s):
    return " ".join([hexbyte(x) for x in s])

def hexbyte(x):
    return hex(x)[2:].zfill(2)

if __name__ == "__main__":
  
    print(haraka256_256([i for i in range(64)]))
    print(haraka512_256([i for i in range(64)]))