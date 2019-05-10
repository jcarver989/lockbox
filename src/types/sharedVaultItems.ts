import { VaultItem, EncryptedVaultItem } from "./vaultItem"

export type SharedVaultItems = {
  itemsOwnerId: string
  itemsOwnerName: string
  items: Array<VaultItem<any>>
}

export type EncryptedSharedVaultItems = {
  itemsOwnerId: string
  itemsOwnerName: string
  items: Array<EncryptedVaultItem>
  hmacOfItems?: string
  lastModified?: number
}
