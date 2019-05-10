import { EncryptionKey, EncryptedData } from "./crypto"

export type VaultItem<T extends VaultItemData> = {
  id: string
  encryptionKey: EncryptionKey
  data: T
}

export type EncryptedVaultItem = {
  id: string
  encryptedKey: EncryptedData
  encryptedData: EncryptedData
}

export type EncryptedVaultItemKeyAndHMAC = EncryptedVaultItem & {
  hmacOfItems: string
  lastModified: number
}

export type EncryptedVaultItemEncryptionKey = {
  userId: string
  itemOwnerId: string
  itemId: string
  encryptedData: EncryptedData
}

export type VaultItemData = {}
