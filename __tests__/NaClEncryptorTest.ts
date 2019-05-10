import { NaClEncryptor } from "../src/NaClEncryptor"

test("Should perform symmetric encryption", () => {
  const encryptor = new NaClEncryptor()
  const encryptionKey = encryptor.generateEncryptionKey()
  const { nonce, cipherText } = encryptor.encrypt(
    JSON.stringify({ text: "hello world!" }),
    encryptionKey
  )
  expect(cipherText).not.toContain("hello world!")

  const result = encryptor.decrypt(cipherText, nonce, encryptionKey)
  expect(JSON.parse(result)).toEqual({ text: "hello world!" })
})

test("should generate a keypair", () => {
  const encryptor = new NaClEncryptor()
  const pair = encryptor.generateKeyPair()
  expect(pair.publicKey).toBeDefined()
  expect(pair.privateKey).toBeDefined()
})

test("should perform asymmetric encryption", () => {
  const encryptor = new NaClEncryptor()
  const alicesKeys = encryptor.generateKeyPair()
  const bobsKeys = encryptor.generateKeyPair()

  const encryptedMessage = encryptor.assymetricEncrypt(
    "Hello Bob",
    bobsKeys.publicKey,
    alicesKeys.privateKey
  )

  const decryptedMessage = encryptor.assymetricDecrypt(
    encryptedMessage.cipherText,
    encryptedMessage.nonce,
    alicesKeys.publicKey,
    bobsKeys.privateKey
  )

  expect(decryptedMessage).toEqual("Hello Bob")
})
