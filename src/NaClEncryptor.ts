import { box, randomBytes, secretbox, verify } from "tweetnacl"
import hmac from "tweetnacl-auth"
import {
  decodeBase64,
  decodeUTF8,
  encodeBase64,
  encodeUTF8
} from "tweetnacl-util"
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
    return { key: encodeBase64(bytes), algorithm: this.algorithm }
  }

  generateKeyPair(): KeyPair {
    const pair = box.keyPair()
    return {
      publicKey: {
        key: encodeBase64(pair.publicKey),
        algorithm: this.algorithm
      },

      privateKey: {
        key: encodeBase64(pair.secretKey),
        algorithm: this.algorithm
      }
    }
  }

  encrypt(message: string, encryptionKey: EncryptionKey): EncryptedData {
    const keyBytes = decodeBase64(encryptionKey.key)
    const nonceBytes = randomBytes(secretbox.nonceLength)
    const messageBytes = decodeUTF8(message)
    const encryptedBytes = secretbox(messageBytes, nonceBytes, keyBytes)

    return {
      nonce: encodeBase64(nonceBytes),
      cipherText: encodeBase64(encryptedBytes)
    }
  }

  decrypt(
    message: string,
    nonce: string,
    decryptionKey: EncryptionKey
  ): string {
    const messageBytes = decodeBase64(message)
    const nonceBytes = decodeBase64(nonce)
    const decryptionKeyBytes = decodeBase64(decryptionKey.key)
    const decrypted = secretbox.open(
      messageBytes,
      nonceBytes,
      decryptionKeyBytes
    )

    if (!decrypted) {
      throw new Error("Could not decrypt message")
    }

    return encodeUTF8(decrypted)
  }

  assymetricEncrypt(
    message: string,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): EncryptedData {
    const messageBytes = decodeUTF8(message)
    const nonceBytes = randomBytes(box.nonceLength)
    const publicKeyBytes = decodeBase64(theirPublicKey.key)
    const secretKeyBytes = decodeBase64(myPrivateKey.key)

    const encryptedBytes = box(
      messageBytes,
      nonceBytes,
      publicKeyBytes,
      secretKeyBytes
    )

    return {
      nonce: encodeBase64(nonceBytes),
      cipherText: encodeBase64(encryptedBytes)
    }
  }

  assymetricDecrypt(
    message: string,
    nonce: string,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): string {
    const messageBytes = decodeBase64(message)
    const nonceBytes = decodeBase64(nonce)
    const publicKeyBytes = decodeBase64(theirPublicKey.key)
    const privateKeyBytes = decodeBase64(myPrivateKey.key)

    const decrypted = box.open(
      messageBytes,
      nonceBytes,
      publicKeyBytes,
      privateKeyBytes
    )

    if (!decrypted) {
      throw new Error("Could not decrypt message")
    }

    return encodeUTF8(decrypted)
  }

  constantTimeEquals(a: string, b: string): boolean {
    return verify(decodeUTF8(a), decodeUTF8(b))
  }

  hmac(message: string, key: EncryptionKey): string {
    return encodeBase64(hmac(decodeUTF8(message), key.key))
  }
}
