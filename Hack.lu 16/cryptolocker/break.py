#!/usr/bin/env python3
import sys
import hashlib
import itertools
from AESCipher import *

CHARS =  [chr(i) for i in xrange(32, 127)]

def break_next(curr_cipher, condition_function):
    res_chars = ''
    g = itertools.product(CHARS, CHARS)
    while True:
        try:
            curr_chars = ''.join(g.next())
        except StopIteration:
            break

        cipher = AESCipher(hashlib.sha256(curr_chars).digest())

        plain = cipher.decrypt(curr_cipher)
        if condition_function(plain):
            res_chars = curr_chars
            curr_cipher = cipher._unpad(plain)
            break

    return curr_cipher, res_chars
 
if __name__ == "__main__":
    # Read file to be encrypted
    filename = 'flag.encrypted'
    ciphertext = open(filename, "rb").read()

    for i in xrange(3):
        ciphertext, curr_chars = break_next(ciphertext, lambda plain: plain[-16:] == '\x10'*16)

    plain, first_chars = break_next(ciphertext, lambda plain: 'PK' == plain[0:2])
    open('{0}.decrypted'.format(filename), 'wb').write(plain)