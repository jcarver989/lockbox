import { aVaultItem } from "../src"
import { EncryptionKey, ENCRYPTION_ALGORITHMS } from "../src/types/crypto"
import { VaultItemEncryptor } from "../src/VaultItemEncryptor"
import { decodeBase64 } from "tweetnacl-util"

const encryptor = new VaultItemEncryptor()
// some "random" 256-bit keys

const vaultKey: EncryptionKey = {
  key: decodeBase64("aaaaaaaaaaaKKflff11EjRDqbHHTkZ0XMMHiqXFsZxg="),
  algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
}

const encryptionKey: EncryptionKey = {
  key: decodeBase64("p6GBVxOkWhjKKflff11EjRDqbHHTkZ0XMMHiqXFsZxg="),
  algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
}

test("when you encrypt a vault then decrypt it the data should be the same", () => {
  // Given a VaultItem
  const item = aVaultItem("item-1", { name: "foo" }, encryptionKey)

  // When we encrypt the plain text
  const encryptedItem = encryptor.encrypt(item, vaultKey)

  // Then the data should be encrypted
  expect(encryptedItem.id).toEqual(item.id)
  expect(encryptedItem.encryptedKey.cipherText).toBeDefined()
  expect(encryptedItem.encryptedKey.nonce).toBeDefined()

  expect(encryptedItem.encryptedData.cipherText).toBeDefined()
  expect(encryptedItem.encryptedData.nonce).toBeDefined()

  // And when we decrypt the encrypted data
  // Then the result should be identical to the original plain text
  const decryptedItem = encryptor.decrypt(encryptedItem, vaultKey)
  expect(decryptedItem).toEqual(item)
})

test("should encrypt and decrypt using an HMAC", () => {
  // Given a VaultItem
  const item = aVaultItem("item-1", { name: "foo" }, encryptionKey)

  // When we encrypt the plain text
  const { encryptedItems, hmac, timestamp } = encryptor.encryptItemsWithHMAC(
    [item],
    vaultKey
  )
  const encryptedItem = encryptedItems[0]

  // Then the data should be encrypted
  expect(encryptedItem.id).toEqual(item.id)
  expect(encryptedItem.encryptedKey.cipherText).toBeDefined()
  expect(encryptedItem.encryptedKey.nonce).toBeDefined()

  expect(encryptedItem.encryptedData.cipherText).toBeDefined()
  expect(encryptedItem.encryptedData.nonce).toBeDefined()

  // And when we decrypt the encrypted data
  // Then the result should be identical to the original plain text

  const decryptedItems = encryptor.decryptItemsWithHMAC(
    encryptedItems,
    vaultKey,
    timestamp,
    hmac
  )
  expect(decryptedItems).toEqual([item])
})

test("tampering with a timestamp thats part of the HMAC should throw an error", () => {
  // Given a VaultItem
  const item = aVaultItem("item-1", { name: "foo" }, encryptionKey)

  // When we encrypt the plain text
  const { encryptedItems, hmac, timestamp } = encryptor.encryptItemsWithHMAC(
    [item],
    vaultKey
  )
  const encryptedItem = encryptedItems[0]

  // And when we decrypt the encrypted data
  // But mess with the timestamp

  expect(() =>
    encryptor.decryptItemsWithHMAC(
      encryptedItems,
      vaultKey,
      timestamp + 10,
      hmac
    )
  ).toThrow()
})

test("Losing an item by accident that should throw an error due to HMACs not matching", () => {
  // Given two VaultItems
  const item = aVaultItem("item-1", { name: "foo" }, encryptionKey)
  const item2 = aVaultItem("item-2", { name: "foo" }, encryptionKey)

  // When we encrypt them
  const { encryptedItems, hmac, timestamp } = encryptor.encryptItemsWithHMAC(
    [item, item2],
    vaultKey
  )

  // But we lose an item
  const items = encryptedItems.slice(1)

  // When we try to decrypt, we should throw an error because the HMACs
  // wont match
  expect(() =>
    encryptor.decryptItemsWithHMAC(items, vaultKey, timestamp, hmac)
  ).toThrow()
})
