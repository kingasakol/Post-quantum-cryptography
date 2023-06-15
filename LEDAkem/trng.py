import secrets

def trng(n):
    return secrets.token_bytes(n)