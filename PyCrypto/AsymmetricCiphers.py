#!/usr/bin/env python3

import Crypto.PublicKey.RSA as CCRSA

""" A class that implements RSA Encryption/Decryption """

class RSA:
    def __init__(self, keysize=2048):
        # RSA keysize is a multiple of 256 bits, and no smaller than 1024 bits
        self.keysize = keysize
        # RSA key object of 'keysize' bits instantiated from 'Crypto.Random'
        self.keyObject = CCRSA.generate(self.keysize)

    def decrypt(self, ciphertext):
        return self.keyObject.decrypt(ciphertext)

    def encrypt(self, plaintext):
        return self.publickeyObject.encrypt(plaintext, 0)[0]

    @property
    def publickeyObject(self):
        # construct a new keyObject carrying only the public information
        return self.keyObject.publickey()

    @property
    def exportPublicKey(self):
        # returns a byte string with the encoded public key
        return self.publickeyObject.exportKey(format='PEM')

    @property
    def exportPrivateKey(self):
        # returns a byte string with the encoded private key
        return self.keyObject.exportKey(format='PEM')

    # save the private key to the disk in the working directory
    def savePrivateKey(self, filename):
        filename += ".pem"
        print("Saving the private as on disk as:", filename)
        with open(filename, 'wb') as f:
            f.write(self.exportPrivateKey)

    # save the private key to the disk in the working directory
    def savePublicKey(self, filename):
        filename += ".pem"
        print("Saving the public key as on disk as:", filename)
        with open(filename, 'wb') as f:
            f.write(self.exportPublicKey)

    def encryptFromFile(self, plaintext, filename):
        with open(filename, 'r') as f:
            publickeyObject = CCRSA.importKey(f.read())
        return publickeyObject.encrypt(plaintext, 0)[0]

    def decryptFromFile(self, ciphertext, filename):
        with open(filename, 'r') as f:
            privatekeyObject = CCRSA.importKey(f.read())
        return privatekeyObject.decrypt(ciphertext)


def main():
    msg = "Progress isn't made by early risers. It's made by lazy men trying to find easier ways to do something."
    # if msg is not in bytes, it must be encoded to bytes
    msg = msg.encode('utf-8')

    """ RSA Example """
    rsa = RSA(2048)
    ciphertext = rsa.encrypt(msg)
    print("Ciphertext:\n", ciphertext)
    plaintext = rsa.decrypt(ciphertext)
    # plaintext received is in bytes, hence must be decoded back
    plaintext = plaintext.decode('utf-8')
    print("\nPlaintext: ", plaintext)

    """ RSA Parameters"""
    print("\nPrivatekey:\n", rsa.exportPrivateKey)
    print("\nPublickey:\n", rsa.exportPublicKey)
    print()

    """ Save RSA keys to disk """
    rsa.savePrivateKey("RSAPrivateKey")
    rsa.savePublicKey("RSAPublicKey")
    print()

    """ RSA Encryption from file """
    ciphertext = rsa.encryptFromFile(msg, "RSAPublicKey.pem")
    print("Ciphertext:\n", ciphertext)

    """ RSA Decryption from file """
    plaintext = rsa.decryptFromFile(ciphertext, "RSAPrivateKey.pem")
    # plaintext received is in bytes, hence must be decoded back
    plaintext = plaintext.decode('utf-8')
    print("\nPlaintext: ", plaintext)

    """ RSA Decryption directly from keyObject """
    plaintext = rsa.decrypt(ciphertext)
    # plaintext received is in bytes, hence must be decoded back
    plaintext = plaintext.decode('utf-8')
    print("\nPlaintext: ", plaintext)


if __name__ == '__main__':
    main()
