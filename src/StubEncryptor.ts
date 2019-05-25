import { verify } from "tweetnacl"
import { decodeUTF8, encodeUTF8 } from "tweetnacl-util"
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
  encryptionKeyGenerator: () => Uint8Array = () =>
    decodeUTF8("encryption-key-123")
  hmacGenerator: (message: Uint8Array, key: EncryptionKey) => Uint8Array = (
    message: Uint8Array,
    key: EncryptionKey
  ) => decodeUTF8("hmac-123")

  withEncryptionKeyGenerator(f: () => Uint8Array) {
    this.encryptionKeyGenerator = f
    return this
  }

  withHMACGenerator(
    f: (message: Uint8Array, key: EncryptionKey) => Uint8Array
  ) {
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
        key: decodeUTF8("public-123"),
        algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
      },

      privateKey: {
        key: decodeUTF8("private-123"),
        algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
      }
    }
  }

  encrypt(message: Uint8Array, key: EncryptionKey): EncryptedData {
    if (this.badKeys.has(key)) {
      throw new Error("Bad Encryption Key Used")
    }

    return {
      cipherText: decodeUTF8(`${message}|${key.key}`),
      nonce: decodeUTF8("nonce-123")
    }
  }

  decrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    key: EncryptionKey
  ): Uint8Array {
    if (this.badKeys.has(key)) {
      throw new Error("Bad Decryption Key Used")
    }

    return decodeUTF8(encodeUTF8(message).split("|")[0])
  }

  assymetricEncrypt(
    message: Uint8Array,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): EncryptedData {
    if (this.badKeys.has(myPrivateKey)) {
      throw new Error("Bad Encryption Key Used")
    }

    return {
      cipherText: decodeUTF8(
        `${message}|${theirPublicKey.key}|${myPrivateKey.key}`
      ),
      nonce: decodeUTF8("nonce-123")
    }
  }

  assymetricDecrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): Uint8Array {
    if (this.badKeys.has(myPrivateKey)) {
      throw new Error("Bad Decryption Key Used")
    }

    return decodeUTF8(encodeUTF8(message).split("|")[0])
  }

  failOnKey(key: EncryptionKey): void {
    this.badKeys.add(key)
  }

  constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    return verify(a, b)
  }

  hmac(message: Uint8Array, key: EncryptionKey): Uint8Array {
    return this.hmacGenerator(message, key)
  }
}
