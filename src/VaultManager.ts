import clone from "lodash.clonedeep"
import { Clock, realClock } from "./clock"
import { anEmptyEncryptedVault, anEmptyVault } from "./index"
import { NaClEncryptor } from "./NaClEncryptor"
import { EncryptionKey } from "./types/crypto"
import { EncryptedVault, Vault } from "./types/vault"
import { VaultItem } from "./types/vaultItem"
import { VaultItemEncryptor } from "./VaultItemEncryptor"

export class VaultManager<T> {
  encryptor: VaultItemEncryptor
  clock: Clock

  constructor(
    encryptor: VaultItemEncryptor = new VaultItemEncryptor(new NaClEncryptor()),
    clock: Clock = realClock()
  ) {
    this.encryptor = encryptor
    this.clock = clock
  }

  create(): {
    vault: Vault<T>
    encryptedVault: EncryptedVault
    vaultKey: EncryptionKey
  } {
    const vaultKey = this.encryptor.generateEncryptionKey()
    const vault = anEmptyVault<T>()
    const encryptedVault = anEmptyEncryptedVault()
    return { vault, vaultKey, encryptedVault }
  }

  addOrUpdateItem<U extends T>(
    vault: EncryptedVault,
    item: VaultItem<U>,
    vaultKey: EncryptionKey
  ): EncryptedVault {
    const updatedVault = clone(vault)
    const encryptedItem = this.encryptor.encrypt(item, vaultKey)
    const existingItemIndex = vault.items.findIndex(_ => _.id === item.id)

    if (existingItemIndex != -1) {
      updatedVault.items[existingItemIndex] = encryptedItem
    } else {
      updatedVault.items.push(encryptedItem)
    }

    const timestamp = this.clock.getTime()
    const hmac = this.encryptor.hmac(updatedVault.items, vaultKey, timestamp)
    updatedVault.lastModified = timestamp
    updatedVault.hmacOfItems = hmac
    return updatedVault
  }

  deleteItem<U extends T>(
    vault: EncryptedVault,
    item: VaultItem<U>,
    vaultKey: EncryptionKey
  ): EncryptedVault {
    const updatedVault = clone(vault)
    updatedVault.items = vault.items.filter(_ => _.id != item.id)
    const timestamp = this.clock.getTime()
    const hmac = this.encryptor.hmac(updatedVault.items, vaultKey, timestamp)
    updatedVault.lastModified = timestamp
    updatedVault.hmacOfItems = hmac
    return updatedVault
  }

  decrypt(vault: EncryptedVault, vaultKey: EncryptionKey): Vault<T> {
    const { hmacOfItems, lastModified } = vault

    const items = this.encryptor.decryptItemsWithHMAC<T>(
      vault.items,
      vaultKey,
      lastModified,
      hmacOfItems
    )

    const sharedItems = vault.sharedItems.map(
      ({ itemsOwnerId, itemsOwnerName, items, hmacOfItems, lastModified }) => {
        const decryptedSharedItems = this.encryptor.decryptItemsWithHMAC<T>(
          items,
          vaultKey,
          lastModified,
          hmacOfItems
        )

        return {
          itemsOwnerId,
          itemsOwnerName,
          items: decryptedSharedItems
        }
      }
    )

    return { items, sharedItems }
  }
}
