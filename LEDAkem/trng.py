import secrets

#  generate secure random numbers
# random byte string with n number of bytes
# true random number generator
def trng(n):
    return secrets.token_bytes(n)