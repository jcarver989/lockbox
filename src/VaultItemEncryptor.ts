import stringify from "json-stable-stringify"
import {
  decodeBase64,
  decodeUTF8,
  encodeBase64,
  encodeUTF8
} from "tweetnacl-util"
import { EncryptionKeyFormatter } from "./EncryptionKeyFormatter"
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

  encrypt<T>(
    item: VaultItem<T>,
    keyEncryptionKey: EncryptionKey
  ): EncryptedVaultItem {
    const { id, data, encryptionKey } = item

    const encryptedData = this.encryptor.encrypt(
      decodeUTF8(JSON.stringify(data)),
      encryptionKey
    )

    const encryptedKey = this.encryptor.encrypt(
      decodeUTF8(EncryptionKeyFormatter.toJSONString(encryptionKey)),
      keyEncryptionKey
    )

    return {
      id,
      encryptedData,
      encryptedKey
    }
  }

  decrypt<T>(
    item: EncryptedVaultItem,
    keyDecryptionKey: EncryptionKey
  ): VaultItem<T> {
    const { id, encryptedKey, encryptedData } = item
    const decryptedKeyBytes = this.encryptor.decrypt(
      encryptedKey.cipherText,
      encryptedKey.nonce,
      keyDecryptionKey
    )
    const decryptedKey = EncryptionKeyFormatter.fromJSONString(
      encodeUTF8(decryptedKeyBytes)
    )

    const decryptedDataBytes = this.encryptor.decrypt(
      encryptedData.cipherText,
      encryptedData.nonce,
      decryptedKey
    )

    return {
      id,
      data: JSON.parse(encodeUTF8(decryptedDataBytes)),
      encryptionKey: decryptedKey
    }
  }

  encryptItemsWithHMAC<T>(
    items: Array<VaultItem<T>>,
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

  decryptItemsWithHMAC<T>(
    items: Array<EncryptedVaultItem>,
    keyDecryptionKey: EncryptionKey,
    lastModified?: number,
    hmac?: string
  ): Array<VaultItem<T>> {
    if (lastModified != null && hmac != null) {
      const newHmac = this.hmac(items, keyDecryptionKey, lastModified)
      if (
        !this.encryptor.constantTimeEquals(
          decodeBase64(hmac),
          decodeBase64(newHmac)
        )
      ) {
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

    // JSON.stringify does not always return keys in the same order
    // so we use a special "stable" stringify method here to ensure
    // a future hmac with the same inputs will match this one
    const message = stringify({
      items: sortedItems,
      numberOfItems: sortedItems.length,
      lastModified: timestamp
    })

    const result = this.encryptor.hmac(decodeUTF8(message), keyEncryptionKey)
    return encodeBase64(result)
  }
}
