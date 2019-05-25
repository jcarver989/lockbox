import {
  decodeBase64,
  encodeBase64,
  decodeUTF8,
  encodeUTF8
} from "tweetnacl-util"
import { NaClEncryptor } from "../src/NaClEncryptor"
import { EncryptionKey } from "../src/types/crypto"

test("Should perform symmetric encryption", () => {
  const encryptor = new NaClEncryptor()
  const encryptionKey = encryptor.generateEncryptionKey()
  const message = JSON.stringify({ text: "hello world!" })
  const { nonce, cipherText } = encryptor.encrypt(
    decodeUTF8(message),
    encryptionKey
  )
  expect(cipherText).not.toContain("hello world!")

  const result = encryptor.decrypt(cipherText, nonce, encryptionKey)
  expect(JSON.parse(encodeUTF8(result))).toEqual({ text: "hello world!" })
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
    decodeUTF8("Hello Bob"),
    bobsKeys.publicKey,
    alicesKeys.privateKey
  )

  const decryptedMessage = encryptor.assymetricDecrypt(
    encryptedMessage.cipherText,
    encryptedMessage.nonce,
    alicesKeys.publicKey,
    bobsKeys.privateKey
  )

  expect(encodeUTF8(decryptedMessage)).toEqual("Hello Bob")
})

test("should match one of tweet-nacl's secretbox test cases", () => {
  const encryptor = new NaClEncryptor()
  const key: EncryptionKey = {
    algorithm: "xSalsa20Poly1305",
    key: decodeBase64("sCrgWptNkUcoU2XJDKQeT1M7gLsSVxW+Z+v46nHbEik=")
  }

  // Test case taken from: https://github.com/dchest/tweetnacl-js/blob/master/test/data/secretbox.random.js
  const nonce = decodeBase64("4MhQGwxeu+QjiJP4PzHQudpMRDxiwiJj")
  const msg = decodeBase64("R1NE6e0vrN1oS5LbuI4Bvto=")
  const cipherText = decodeBase64(
    "GSn0qNxPfTyAHOkNl25ViM8xm0pr1uekERB+UGZZO1Kd"
  )

  expect(encryptor.encrypt(msg, key, nonce).cipherText).toEqual(cipherText)
})
