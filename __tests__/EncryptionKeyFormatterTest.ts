import { EncryptionKeyFormatter } from "../src/EncryptionKeyFormatter"
import { EncryptionKey, ENCRYPTION_ALGORITHMS } from "../src/types/crypto"
import { decodeBase64, decodeUTF8 } from "tweetnacl-util"

const vaultKey: EncryptionKey = {
  key: decodeUTF8("secret-key-123"),
  algorithm: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
}
const base32VaultKey = "V1-ONSWG-4TFOQ-WWWZL-ZFUYT-EMY="

test("should format a VaultKey to base32 so humans can type it in to recover it", () => {
  const encoded = EncryptionKeyFormatter.toBase32(vaultKey)
  expect(encoded).toEqual(base32VaultKey)
})

test("should recover a VaultKey from base32", () => {
  const key = EncryptionKeyFormatter.fromBase32(base32VaultKey)
  expect(key).toEqual(vaultKey)
})

test("should strip whitespace the user accidentially enters", () => {
  const key = EncryptionKeyFormatter.fromBase32(
    `   ${base32VaultKey.charAt(0)} ${base32VaultKey.slice(1)}    `
  )
  expect(key).toEqual(vaultKey)
})

test("should convert a VaultKey to a QR code", async () => {
  const key = await EncryptionKeyFormatter.toQRCode(vaultKey, 50)
  expect(key).toContain(
    '<svg xmlns="http://www.w3.org/2000/svg" width="50" height="50"'
  )
})

test("should be case sensitive when encoding", () => {
  const encoded = EncryptionKeyFormatter.toBase32({
    ...vaultKey,
    key: decodeUTF8("secret-key-123".toUpperCase())
  })
  expect(encoded).not.toEqual(base32VaultKey)
})
