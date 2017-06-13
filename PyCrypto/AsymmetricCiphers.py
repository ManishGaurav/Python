#!/usr/bin/env python3

import Crypto.PublicKey.RSA as CCRSA
import Crypto.Cipher.PKCS1_OAEP as CCOAEP

""" A wrapper class for textbook-RSA Encryption/Decryption """


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
    # returns a byte string with the encoded public key
    def exportPublicKey(self):
        return self.publickeyObject.exportKey(format='PEM')

    @property
    # returns a byte string with the encoded private key
    def exportPrivateKey(self):
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


""" A wrapper class for Optimal Asymmetric Encryption Padding RSA Encryption/Decryption """


class RSAES_OAEP:
    def __init__(self, keysize=2048):
        # RSA keysize is a multiple of 256 bits, and no smaller than 1024 bits
        self.keysize = keysize
        # RSA key object of 'keysize' bits instantiated from 'Crypto.Random'
        self.keyObject = CCRSA.generate(self.keysize)

    def decrypt(self, ciphertext):
        cipherObject = CCOAEP.new(self.keyObject)
        plaintext = cipherObject.decrypt(ciphertext)
        return plaintext

    def encrypt(self, plaintext):
        cipherObject = CCOAEP.new(self.keyObject)
        ciphertext = cipherObject.encrypt(plaintext)
        return ciphertext

    @property
    def publickeyObject(self):
        # construct a new keyObject carrying only the public information
        return self.keyObject.publickey()

    @property
    # returns a byte string with the encoded public key
    def exportPublicKey(self):
        return self.publickeyObject.exportKey(format='PEM')

    @property
    # returns a byte string with the encoded private key
    def exportPrivateKey(self):
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
        cipherObject = CCOAEP.new(publickeyObject)
        ciphertext = cipherObject.encrypt(plaintext)
        return ciphertext

    def decryptFromFile(self, ciphertext, filename):
        with open(filename, 'r') as f:
            privatekeyObject = CCRSA.importKey(f.read())
        cipherObject = CCOAEP.new(privatekeyObject)
        plaintext = cipherObject.decrypt(ciphertext)
        return plaintext


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

    """ RSAES-OAEP Example """
    rsaoaep = RSAES_OAEP(2048)
    ciphertext = rsaoaep.encrypt(msg)
    print("Ciphertext:\n", ciphertext)
    plaintext = rsaoaep.decrypt(ciphertext)
    # plaintext received is in bytes, hence must be decoded back
    plaintext = plaintext.decode('utf-8')
    print("\nPlaintext: ", plaintext)

    """ RSAES-OAEP Parameters"""
    print("\nPrivatekey:\n", rsaoaep.exportPrivateKey)
    print("\nPublickey:\n", rsaoaep.exportPublicKey)
    print()

    """ Save RSAES-OAEP keys to disk """
    rsaoaep.savePrivateKey("RSAES-OAE-PrivateKey")
    rsaoaep.savePublicKey("RSAES-OAEP-PublicKey")
    print()

    """ RSAES-OAEP Encryption from file """
    ciphertext = rsaoaep.encryptFromFile(msg, "RSAES-OAEP-PublicKey.pem")
    print("Ciphertext:\n", ciphertext)

    """ RSAES-OAEP Decryption from file """
    plaintext = rsaoaep.decryptFromFile(ciphertext, "RSAES-OAE-PrivateKey.pem")
    # plaintext received is in bytes, hence must be decoded back
    plaintext = plaintext.decode('utf-8')
    print("\nPlaintext: ", plaintext)

    """ RSAES-OAEP Decryption directly from keyObject """
    plaintext = rsaoaep.decrypt(ciphertext)
    # plaintext received is in bytes, hence must be decoded back
    plaintext = plaintext.decode('utf-8')
    print("\nPlaintext: ", plaintext)


if __name__ == '__main__':
    main()
