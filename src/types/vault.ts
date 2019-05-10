import { EncryptedSharedVaultItems, SharedVaultItems } from "./sharedVaultItems"
import { EncryptedVaultItem, VaultItem } from "./vaultItem"

export type Vault = {
  items: Array<VaultItem<any>>
  sharedItems: Array<SharedVaultItems>
}

export type EncryptedVault = {
  items: Array<EncryptedVaultItem>
  sharedItems: Array<EncryptedSharedVaultItems>
  sharedItemsEncryptedWithOwnersVaultKey: Array<EncryptedSharedVaultItems>
  hmacOfItems?: string
  lastModified?: number
}
