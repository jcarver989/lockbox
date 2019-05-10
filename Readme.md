# Vault Core

Library for creating a client-side encrypted password manager. Uses 256-bit encryption keys with xsalsa20-poly1305.

## Features

- Encrypt/decrypt arbitrary JSON data in your own personal Vault (backed by [tweet-nacl](https://github.com/dchest/tweetnacl-js))
- Uses a fully random 256-bit encryption key to protect your data (vs a password derived approach that has less entropy)
- Decryption includes a HMAC check to ensure your Vault items haven't been tampered with or corrupted
- Helpers to encode your master vault key as a QR code or base-32 string (looks like an old cd license-key) for easy storage.

## Example Usage

```typescript
import { VaultManager } from "./VaultManager"
import { aVaultItem } from "./index"

// Create a Vault (make sure you store your vaultKey somewhere safe!)
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

// Persist your Vault somewhere - a local file, s3 etc. (you must write this function yourself)
saveToFile(encryptedUpdatedVault)

// Sometime later, decyrpt your Vault
const decryptedVault = vaultManager.decrypt(encryptedUpdatedVault, vaultKey)
```

## Encoding Encryption Keys

```typescript
import { EncryptionKeyFormatter } from "./EncryptionKeyFormatter"
import { VaultManager } from "./VaultManager"

// Given a Vault Key
const vaultManager = new VaultManager()
const { vaultKey } = vaultManager.create()

// You can print it and store it as an SVG QR code
const formatter = new EncryptionKeyFormatter()
const qrCode = await formatter.toQRCode(vaultKey, 200) // 200 is the QR code's size as an SVG

// Then scan it using a laptop/phone camera to "input" your key
const scannedKey = formatter.fromQRCode(qrCode)

// Similarly you can encode/decode vaultKey to/from a base32 string
const stringKey = formatter.toBase32(vaultKey)
const recoveredKey = formatter.fromBase32(stringKey)
```
