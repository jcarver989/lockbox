import stringify from "json-stable-stringify"
import { NaClEncryptor } from "./NaClEncryptor"
import { EncryptionKey, Encryptor, KeyPair } from "./types/crypto"
import { EncryptedVaultItem, VaultItem } from "./types/vaultItem"

/** Uses an Encryptor to encrypt/decrypt Vault items and their keys.
 *
 * Each VaultItem should be encrypted with its own randomly generated encryption key.
 * Each VaultItem's encryption key should be encrypted using the user's VaultKey (256-bit key stored on their device + printed out on their VaultKit)
 */

export class VaultItemEncryptor {
  encryptor: Encryptor

  constructor(encryptor: Encryptor = new NaClEncryptor()) {
    this.encryptor = encryptor
  }

  generateEncryptionKey(): EncryptionKey {
    return this.encryptor.generateEncryptionKey()
  }

  generateKeyPair(): KeyPair {
    return this.encryptor.generateKeyPair()
  }

  encrypt(
    item: VaultItem<any>,
    keyEncryptionKey: EncryptionKey
  ): EncryptedVaultItem {
    const { id, data, encryptionKey } = item
    const encryptedData = this.encryptor.encrypt(
      JSON.stringify(data),
      encryptionKey
    )

    const encryptedKey = this.encryptor.encrypt(
      JSON.stringify(encryptionKey),
      keyEncryptionKey
    )

    return {
      id: item.id,
      encryptedData,
      encryptedKey
    }
  }

  decrypt(
    item: EncryptedVaultItem,
    keyDecryptionKey: EncryptionKey
  ): VaultItem<any> {
    const { id, encryptedKey, encryptedData } = item
    const decryptedKey = JSON.parse(
      this.encryptor.decrypt(
        encryptedKey.cipherText,
        encryptedKey.nonce,
        keyDecryptionKey
      )
    )

    const decryptedData = JSON.parse(
      this.encryptor.decrypt(
        encryptedData.cipherText,
        encryptedData.nonce,
        decryptedKey
      )
    )

    return {
      id,
      data: decryptedData,
      encryptionKey: decryptedKey
    }
  }

  encryptItemsWithHMAC(
    items: Array<VaultItem<any>>,
    keyEncryptionKey: EncryptionKey
  ): {
    encryptedItems: Array<EncryptedVaultItem>
    timestamp: number
    hmac: string
  } {
    const encryptedItems = items.map(i => this.encrypt(i, keyEncryptionKey))
    const timestamp = new Date().getTime()
    const hmac = this.hmac(encryptedItems, keyEncryptionKey, timestamp)
    return {
      encryptedItems,
      timestamp,
      hmac
    }
  }

  decryptItemsWithHMAC(
    items: Array<EncryptedVaultItem>,
    keyDecryptionKey: EncryptionKey,
    lastModified?: number,
    hmac?: string
  ): Array<VaultItem<any>> {
    if (lastModified != null && hmac != null) {
      const newHmac = this.hmac(items, keyDecryptionKey, lastModified)
      if (!this.encryptor.constantTimeEquals(hmac, newHmac)) {
        throw new Error(
          "HMACs do not match. Vault items are either missing, or have been tampered with."
        )
      }

      return items.map(i => this.decrypt(i, keyDecryptionKey))
    } else {
      throw new Error("lastModified and/or hmacOfItems was undefined")
    }
  }

  hmac(
    items: Array<EncryptedVaultItem>,
    keyEncryptionKey: EncryptionKey,
    timestamp: number
  ): string {
    // Sort items by id to avoid HMAC failure due to array order changing
    const sortedItems = items.slice(0).sort((a, b) => {
      if (a.id < b.id) {
        return -1
      } else if (a.id === b.id) {
        return 0
      } else {
        return 1
      }
    })

    const message = stringify({
      items: sortedItems,
      numberOfItems: sortedItems.length,
      lastModified: timestamp
    })

    return this.encryptor.hmac(message, keyEncryptionKey)
  }
}
