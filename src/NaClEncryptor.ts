import { box, randomBytes, secretbox, verify } from "tweetnacl"
import tweetNaclHmac from "tweetnacl-auth"
import {
  EncryptedData,
  EncryptionKey,
  ENCRYPTION_ALGORITHMS,
  Encryptor,
  KeyPair
} from "./types/crypto"

/** A thin wrapper around: https://github.com/dchest/tweetnacl-js#audits
    The library linked above underwent a security audit by Cure53 in early 2017. 
    See Readme on github for more details.
 */
export class NaClEncryptor implements Encryptor {
  algorithm = ENCRYPTION_ALGORITHMS.xSalsa20Poly1305

  generateEncryptionKey(): EncryptionKey {
    const bytes = randomBytes(secretbox.keyLength)
    return { key: bytes, algorithm: this.algorithm }
  }

  generateKeyPair(): KeyPair {
    const pair = box.keyPair()
    return {
      publicKey: {
        key: pair.publicKey,
        algorithm: this.algorithm
      },

      privateKey: {
        key: pair.secretKey,
        algorithm: this.algorithm
      }
    }
  }

  encrypt(
    message: Uint8Array,
    encryptionKey: EncryptionKey,
    nonce: Uint8Array = randomBytes(secretbox.nonceLength)
  ): EncryptedData {
    const encryptedBytes = secretbox(message, nonce, encryptionKey.key)

    return {
      nonce: nonce,
      cipherText: encryptedBytes
    }
  }

  decrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    decryptionKey: EncryptionKey
  ): Uint8Array {
    const decrypted = secretbox.open(message, nonce, decryptionKey.key)

    if (!decrypted) {
      throw new Error("Could not decrypt message")
    }

    return decrypted
  }

  assymetricEncrypt(
    message: Uint8Array,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): EncryptedData {
    const messageBytes = message
    const nonceBytes = randomBytes(box.nonceLength)
    const publicKeyBytes = theirPublicKey.key
    const secretKeyBytes = myPrivateKey.key

    const encryptedBytes = box(
      messageBytes,
      nonceBytes,
      publicKeyBytes,
      secretKeyBytes
    )

    return {
      nonce: nonceBytes,
      cipherText: encryptedBytes
    }
  }

  assymetricDecrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): Uint8Array {
    const messageBytes = message
    const nonceBytes = nonce
    const publicKeyBytes = theirPublicKey.key
    const privateKeyBytes = myPrivateKey.key

    const decrypted = box.open(
      messageBytes,
      nonceBytes,
      publicKeyBytes,
      privateKeyBytes
    )

    if (!decrypted) {
      throw new Error("Could not decrypt message")
    }

    return decrypted
  }

  constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    return verify(a, b)
  }

  hmac(message: Uint8Array, key: EncryptionKey): Uint8Array {
    return tweetNaclHmac(message, key.key)
  }
}
