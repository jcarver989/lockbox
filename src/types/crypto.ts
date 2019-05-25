/** Represents a specific encryption algorithm (used to tag encrypted data with human readable metadata) */
export const ENCRYPTION_ALGORITHMS: { [key: string]: string } = {
  xSalsa20Poly1305: "xSalsa20Poly1305"
}

export type EncryptionAlgorithm = keyof typeof ENCRYPTION_ALGORITHMS

/** An Encryption key - e.g. the user's master Vault Key or an indiviudal item's encryption key */
export type EncryptionKey = {
  key: Uint8Array

  // some encryption algorithms are picky about key lengths, so we tag
  // this key with the algorithm we intended to use it with
  algorithm: EncryptionAlgorithm
}

/** Represents encrypted JSON data */
export type EncryptedData = {
  nonce: Uint8Array
  cipherText: Uint8Array
}

/** A Public / Private Keypair */
export type KeyPair = {
  publicKey: EncryptionKey
  privateKey: EncryptionKey
}

/** Encapsulates an encryption + HMAC "strategy" - e.g. AES-GCM, xsalsa20-poly1305 etc.

    Since encryption algorithms are often coupled to key generation strategies and/or key lengths
    The methods to generate appropriate keys are included as part of this interface.
 */
export interface Encryptor {
  // this field is just metadata for humans
  algorithm: EncryptionAlgorithm

  // Use this whenever you need to generate a symmetric encryption key
  generateEncryptionKey(): EncryptionKey

  // Use this whenever you need to generate an asymmetric key pair
  generateKeyPair(): KeyPair

  // EncryptedData fields should be base64 encoded to allow sending of encrypted data over HTTPS
  encrypt(message: Uint8Array, key: EncryptionKey): EncryptedData

  // Should return utf8 (not base64) encoded string as plaintext might contain utf8 characters
  decrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    key: EncryptionKey
  ): Uint8Array

  assymetricEncrypt(
    message: Uint8Array,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): EncryptedData

  assymetricDecrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    theirPublicKey: EncryptionKey,
    myPrivateKey: EncryptionKey
  ): Uint8Array

  // To avoid timing attacks, make sure you use this to compare HMACs, not ==.
  constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean

  hmac(message: Uint8Array, key: EncryptionKey): Uint8Array
}
