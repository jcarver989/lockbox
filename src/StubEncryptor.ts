import { verify } from "tweetnacl"
import { decodeUTF8 } from "tweetnacl-util"
import {
  EncryptedData,
  EncryptionKey,
  ENCRYPTION_ALGORITHMS,
  Encryptor,
  KeyPair
} from "./types/crypto"

/** A StubEncryptor for unit testing with */

export class StubEncryptor implements Encryptor {
  algorithm = ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
  badKeys = new Set<EncryptionKey>()
  encryptionKeyGenerator: () => string = () => "encryption-key-123"
  hmacGenerator: (message: string, key: EncryptionKey) => string = (
    message: string,
    key: EncryptionKey
  ) => "hmac-123"

  withEncryptionKeyGenerator(f: () => string) {
    this.encryptionKeyGenerator = f
    return this
  }

  withHMACGenerator(f: (message: string, key: EncryptionKey) => string) {
    this.hmacGenerator = f
    return this
  }

  generateEncryptionKey(): EncryptionKey {
    return {
      key: this.encryptionKeyGenerator(),
      algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
    }
  }

  generateKeyPair(): KeyPair {
    return {
      publicKey: {
        key: "public-123",
        algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
      },

      privateKey: {
        key: "private-123",
        algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
      }
    }
  }

  encrypt(message: string, key: EncryptionKey): EncryptedData {
    if (this.badKeys.has(key)) {
      throw new Error("Bad Encryption Key Used")
    }

    return {
      cipherText: `${message}|${key.key}`,
      nonce: "nonce-123"
    }
  }

  decrypt(message: string, nonce: string, key: EncryptionKey): string {
    if (this.badKeys.has(key)) {
      throw new Error("Bad Decryption Key Used")
    }

    return message.split("|")[0]
  }

  assymetricEncrypt(
    message: string,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): EncryptedData {
    if (this.badKeys.has(myPrivateKey)) {
      throw new Error("Bad Encryption Key Used")
    }

    return {
      cipherText: `${message}|${theirPublicKey.key}|${myPrivateKey.key}`,
      nonce: "nonce-123"
    }
  }

  assymetricDecrypt(
    message: string,
    nonce: string,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): string {
    if (this.badKeys.has(myPrivateKey)) {
      throw new Error("Bad Decryption Key Used")
    }

    return message.split("|")[0]
  }

  failOnKey(key: EncryptionKey): void {
    this.badKeys.add(key)
  }

  constantTimeEquals(a: string, b: string): boolean {
    return verify(decodeUTF8(a), decodeUTF8(b))
  }

  hmac(message: string, key: EncryptionKey): string {
    return this.hmacGenerator(message, key)
  }
}
