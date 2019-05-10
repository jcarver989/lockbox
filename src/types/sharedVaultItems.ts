import { VaultItem, EncryptedVaultItem } from "./vaultItem"

export type SharedVaultItems<T> = {
  itemsOwnerId: string
  itemsOwnerName: string
  items: Array<VaultItem<T>>
}

export type EncryptedSharedVaultItems = {
  itemsOwnerId: string
  itemsOwnerName: string
  items: Array<EncryptedVaultItem>
  hmacOfItems?: string
  lastModified?: number
}
