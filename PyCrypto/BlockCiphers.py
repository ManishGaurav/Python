#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto import Random

""" A class that implements AES Encryption/Decryption Scheme in ECB/CBC mode
    Note: plaintext, key, iv must be in bytes, ciphertext is also in bytes
"""


class MGvAES:
    def __init__(self, keysize=16):
        self.blocksize = 16  # AES blocksize is 16 bytes
        self.keysize = keysize  # AES keysize is 16/24/32 bytes

    def decrypt(self, ciphertext, key, iv=None):
        key = self.properKeysize(key)
        if iv is None:
            cipherObject = AES.new(key, AES.MODE_ECB)
        else:
            cipherObject = AES.new(key, AES.MODE_CBC, iv)
        plaintextWithPads = cipherObject.decrypt(ciphertext)
        plaintextWithoutPads = plaintextWithPads[:-plaintextWithPads[-1]]
        return plaintextWithoutPads

    def encrypt(self, plaintext, key, iv=None):
        plaintext = self.properBlocksize(plaintext)
        key = self.properKeysize(key)
        if iv is None:
            cipherObject = AES.new(key, AES.MODE_ECB)
        else:
            cipherObject = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipherObject.encrypt(plaintext)
        return ciphertext

    # PKCS#7 padding scheme
    def properBlocksize(self, plaintext):
        length = self.blocksize - (len(plaintext) % self.blocksize)
        return plaintext + bytes([length]) * length

    # if len(key) < keysize then pad key, else slice key
    def properKeysize(self, key):
        if len(key) < self.keysize:
            length = self.keysize - (len(key) % self.keysize)
            return key + bytes([length]) * length
        else:
            return key[:self.keysize]


""" A class that implements DES3 Encryption/Decryption Scheme in ECB/CBC mode
    Note: plaintext, key, iv must be in bytes, ciphertext is also in bytes
"""


class MGvDES3:
    def __init__(self, keysize=16):
        self.blocksize = 8  # DES3 blocksize is 8 bytes
        self.keysize = keysize  # DES3 keysize is 16/24 bytes

    def decrypt(self, ciphertext, key, iv=None):
        key = self.properKeysize(key)
        if iv is None:
            cipherObject = DES3.new(key, DES3.MODE_ECB)
        else:
            cipherObject = DES3.new(key, DES3.MODE_CBC, iv)
        plaintextWithPads = cipherObject.decrypt(ciphertext)
        plaintextWithoutPads = plaintextWithPads[:-plaintextWithPads[-1]]
        return plaintextWithoutPads

    def encrypt(self, plaintext, key, iv=None):
        plaintext = self.properBlocksize(plaintext)
        key = self.properKeysize(key)
        if iv is None:
            cipherObject = DES3.new(key, DES3.MODE_ECB)
        else:
            cipherObject = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipherObject.encrypt(plaintext)
        return ciphertext

    # PKCS#7 padding scheme
    def properBlocksize(self, plaintext):
        length = self.blocksize - (len(plaintext) % self.blocksize)
        return plaintext + bytes([length]) * length

    # if len(key) < keysize then pad key, else slice key
    def properKeysize(self, key):
        if len(key) < self.keysize:
            length = self.keysize - (len(key) % self.keysize)
            return key + bytes([length]) * length
        else:
            return key[:self.keysize]


def main():
    msg = "Progress isn't made by early risers. It's made by lazy men trying to find easier ways to do something."
    key = "--Robert Heinlein"
    # if msg and key are not in bytes, they must be converted to bytes
    msg = msg.encode('utf-8')
    key = key.encode('utf-8')

    """ AES ECB Example """
    aes = MGvAES(24)  # AES encryption with keysize of 24 bytes
    ciphertext = aes.encrypt(msg, key)
    print("Ciphertext:\t", ciphertext)
    plaintext = aes.decrypt(ciphertext, key)
    # plaintext received is in bytes, hence must be converted
    plaintext = plaintext.decode('utf-8')
    print("Plaintext:\t", plaintext)

    """ AES CBC Example """
    aes = MGvAES(32)  # AES encryption with keysize of 32 bytes
    iv = Random.new().read(aes.blocksize)  # generate iv equal to blocksize in bytes
    ciphertext = aes.encrypt(msg, key, iv)
    print("Ciphertext:\t", ciphertext)
    plaintext = aes.decrypt(ciphertext, key, iv)
    # plaintext received is in bytes, hence must be converted
    plaintext = plaintext.decode('utf-8')
    print("Plaintext:\t", plaintext)

    """ DES3 ECB Example """
    des3 = MGvDES3()  # DES3 encryption with keysize of 16 bytes
    ciphertext = des3.encrypt(msg, key)
    print("Ciphertext:\t", ciphertext)
    plaintext = des3.decrypt(ciphertext, key)
    # plaintext received is in bytes, hence must be converted
    plaintext = plaintext.decode('utf-8')
    print("Plaintext:\t", plaintext)

    """ DES3 CBC Example """
    des3 = MGvDES3(24)  # DES3 encryption with keysize of 24 bytes
    # generate iv equal to blocksize in bytes
    iv = Random.new().read(des3.blocksize)
    ciphertext = des3.encrypt(msg, key, iv)
    print("Ciphertext:\t", ciphertext)
    plaintext = des3.decrypt(ciphertext, key, iv)
    # plaintext received is in bytes, hence must be converted
    plaintext = plaintext.decode('utf-8')
    print("Plaintext:\t", plaintext)


if __name__ == '__main__':
    main()
