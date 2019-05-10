# Vault Core

Library for creating a client-side encrypted password manager. Uses 256-bit encryption keys with xsalsa20-poly1305.

## Example Usage

```typescript
import { VaultManager } from "./VaultManager"
import { aVaultItem } from "./index"

// Create a Vault
const vaultManager = new VaultManager()
const { vaultKey, encryptedVault } = vaultManager.create()

// And an item
const item = aVaultItem(
  // Give your vault item a unique id
  "id-123",

  // Add whatever data you want
  { name: "foo" },

  // And its own unique encryption key
  // Your item's encryption key will encrypt the data above
  // and your vaultKey will encrypt this key (this makes sharing items with other people possible)
  vaultManager.encryptor.generateEncryptionKey()
)

// Add your item to your vault
const encryptedUpdatedVault = vaultManager.addOrUpdateItem(
  encryptedVault,
  item,
  vaultKey
)

// Persist your Vault somewhere - a local file, s3 etc.
saveToFile(encryptedUpdatedVault)

// Sometime later, decyrpt your Vault
const decryptedVault = vaultManager.decrypt(encryptedUpdatedVault, vaultKey)
```
