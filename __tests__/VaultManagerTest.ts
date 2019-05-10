import { realClock, stubClock } from "../src/clock"
import {
  anEmptyEncryptedVault,
  anEmptyVault,
  anEncryptedVaultItem
} from "../src/index"
import { NaClEncryptor } from "../src/NaClEncryptor"
import { StubEncryptor } from "../src/StubEncryptor"
import { VaultItem } from "../src/types/vaultItem"
import { VaultItemEncryptor } from "../src/VaultItemEncryptor"
import { VaultManager } from "../src/VaultManager"

test("should create a vault", () => {
  const encryptor = new StubEncryptor()
    .withEncryptionKeyGenerator(() => "encryption-key-123")
    .withHMACGenerator((message, key) => "hmac-123")

  const vaultManager = new VaultManager<StubItem>(
    new VaultItemEncryptor(encryptor),
    stubClock(1000)
  )

  const { vault, vaultKey } = vaultManager.create()
  expect(vault).toEqual(anEmptyVault())
  expect(vaultKey.key).toEqual("encryption-key-123")
})

test("should add item to the Vault", () => {
  const encryptor = new StubEncryptor()
    .withEncryptionKeyGenerator(() => "encryption-key-123")
    .withHMACGenerator((message, key) => "hmac-123")

  const vaultKey = encryptor.generateEncryptionKey()

  const vaultManager = new VaultManager<StubItem>(
    new VaultItemEncryptor(encryptor),
    stubClock(1000)
  )

  const encryptedVault = anEmptyEncryptedVault()

  const item = aMiscVaultItem()
  const response = vaultManager.addOrUpdateItem(encryptedVault, item, vaultKey)

  expect(response.items.length).toEqual(1)
  expect(response.hmacOfItems).toEqual("hmac-123")
  expect(response.lastModified).toEqual(1000)
  expect(response.items[0].id).toEqual(item.id)
})

test("should delete an item", () => {
  const encryptor = new StubEncryptor()
    .withEncryptionKeyGenerator(() => "encryption-key-123")
    .withHMACGenerator((message, key) => "hmac-123")

  const vaultKey = encryptor.generateEncryptionKey()

  const vaultManager = new VaultManager<StubItem>(
    new VaultItemEncryptor(encryptor),
    stubClock(1000)
  )

  const encryptedVault = anEmptyEncryptedVault()
  encryptedVault.items = [anEncryptedVaultItem("item-1")]

  const item = aMiscVaultItem()
  item.id = "item-1"
  const response = vaultManager.deleteItem(encryptedVault, item, vaultKey)

  expect(response.items.length).toEqual(0)
  expect(response.hmacOfItems).toEqual("hmac-123")
  expect(response.lastModified).toEqual(1000)
  expect(response.items.length).toEqual(0)
})

test("should work with a real implementation", () => {
  // Given we create a "real" Vault
  const encryptor = new NaClEncryptor()
  const itemEncryptor = new VaultItemEncryptor(encryptor)
  const vaultManager = new VaultManager<StubItem>(itemEncryptor, realClock())
  const { vaultKey, encryptedVault } = vaultManager.create()

  // And then we add an item to it
  const item = aMiscVaultItem(itemEncryptor)
  const updatedEncryptedVault = vaultManager.addOrUpdateItem(
    encryptedVault,
    item,
    vaultKey
  )

  // When we decrypt it
  const updatedDecryptedVault = vaultManager.decrypt(
    updatedEncryptedVault,
    vaultKey
  )

  // Then we expect our item to be decrypted
  expect(updatedDecryptedVault.items).toEqual([item])
})

type StubItem = { name: string }

export function aMiscVaultItem(
  encryptor: VaultItemEncryptor = new VaultItemEncryptor()
): VaultItem<StubItem> {
  return {
    id: "123",
    encryptionKey: encryptor.generateEncryptionKey(),
    data: {
      name: "item 1"
    }
  }
}
