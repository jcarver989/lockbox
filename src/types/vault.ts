import { EncryptedSharedVaultItems, SharedVaultItems } from "./sharedVaultItems"
import { EncryptedVaultItem, VaultItem } from "./vaultItem"

export type Vault<T> = {
  items: Array<VaultItem<T>>
  sharedItems: Array<SharedVaultItems<T>>
}

export type EncryptedVault = {
  items: Array<EncryptedVaultItem>
  sharedItems: Array<EncryptedSharedVaultItems>
  sharedItemsEncryptedWithOwnersVaultKey: Array<EncryptedSharedVaultItems>
  hmacOfItems?: string
  lastModified?: number
}
