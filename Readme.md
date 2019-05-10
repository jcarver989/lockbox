# Vault Core

Library for creating a client-side encrypted password manager. Uses 256-bit encryption keys with xsalsa20-poly1305.

## Example Usage

```
import { VaultManager } from "./VaultManager"
import { aVaultItem } from "./index"

const vaultManager = new VaultManager()
const { vaultKey, encryptedVault } = vaultManager.create()

const item = aVaultItem(
  "id-123",
  { name: "foo" },

  // Each Vault item has its own encryption key
  // that will be encrypted with your vaultKey
  vaultManager.encryptor.generateEncryptionKey()
)

const updatedVault = vaultManager.addOrUpdateItem(
  encryptedVault,
  item,
  vaultKey
)

saveToFile(updatedVault)
```
