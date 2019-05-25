import { EncryptedData, EncryptionKey } from "./types/crypto"
import { EncryptedVault, Vault } from "./types/vault"
import {
  EncryptedVaultItem,
  EncryptedVaultItemEncryptionKey,
  VaultItem
} from "./types/VaultItem"
import { decodeUTF8 } from "tweetnacl-util"

export function anEmptyVault<T>(): Vault<T> {
  return {
    items: [],
    sharedItems: []
  }
}

export function anEmptyEncryptedVault(): EncryptedVault {
  return {
    items: [],
    sharedItems: [],
    sharedItemsEncryptedWithOwnersVaultKey: []
  }
}

export function aVaultItem<T>(
  id: string,
  data: T,
  encryptionKey: EncryptionKey
): VaultItem<T> {
  return {
    id,
    encryptionKey,
    data: data
  }
}

export function anEncryptedVaultItem(id: string): EncryptedVaultItem {
  return {
    id,
    encryptedData: someEncryptedData(),
    encryptedKey: someEncryptedData()
  }
}

export function anEncryptedVaultItemEncryptionKey(): EncryptedVaultItemEncryptionKey {
  return {
    userId: "user-1",
    itemOwnerId: "owner-1",
    itemId: "item-1",
    encryptedData: someEncryptedData()
  }
}

export function someEncryptedData(): EncryptedData {
  return {
    cipherText: decodeUTF8("cipher"),
    nonce: decodeUTF8("123")
  }
}
