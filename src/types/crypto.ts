/** Represents a specific encryption algorithm (used to tag encrypted data with human readable metadata) */
export const ENCRYPTION_ALGORITHMS: { [key: string]: string } = {
  xSalsa20Poly1305: "xSalsa20Poly1305"
}

export type EncryptionAlgorithm = keyof typeof ENCRYPTION_ALGORITHMS

export type EncryptionKey = {
  key: string
  algorithm: EncryptionAlgorithm // algorithm this encryption key is intended to be used with
}

export type EncryptedData = {
  nonce: string
  cipherText: string
}

export type KeyPair = {
  publicKey: EncryptionKey
  privateKey: EncryptionKey
}

/** Encapsulates an encryption "strategy" - e.g. AES-GCM, xsalsa20-poly1305 etc.

    Since encryption algorithms are often coupled to key generation strategies and/or key lengths
    The methods to generate appropriate keys are included as part of this interface.
 */
export interface Encryptor {
  // this field is just metadata for humans
  algorithm: EncryptionAlgorithm

  // should return base64 encoded string
  generateEncryptionKey(): EncryptionKey

  generateKeyPair(): KeyPair

  // EncryptedData fields should be base64 encoded since we want to send encrypted data over HTTPS
  encrypt(message: string, key: EncryptionKey): EncryptedData

  // should return utf8 (not base64) encoded string as plaintext might contain utf8 characters
  decrypt(message: string, nonce: string, key: EncryptionKey): string

  assymetricEncrypt(
    message: string,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): EncryptedData

  assymetricDecrypt(
    message: string,
    nonce: string,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): string

  constantTimeEquals(a: string, b: string): boolean

  hmac(message: string, key: EncryptionKey): string
}
