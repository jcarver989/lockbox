import * as base32 from "hi-base32"
import QRCode from "qrcode"
import {
  decodeBase64,
  decodeUTF8,
  encodeUTF8,
  encodeBase64
} from "tweetnacl-util"
import {
  EncryptionAlgorithm,
  EncryptionKey,
  ENCRYPTION_ALGORITHMS
} from "./types/crypto"

const VERSION_TO_ALGORITHM: { [key: string]: string } = {
  V1: ENCRYPTION_ALGORITHMS.xSalsa20Poly1305
}

const ALGORITHM_TO_VERSION: { [key: string]: string } = {
  [ENCRYPTION_ALGORITHMS.xSalsa20Poly1305]: "V1"
}

/** Converts an Encryption key to/from various formats - e.g. base32, QRCode etc. */
export class EncryptionKeyFormatter {
  static toJSONString(key: EncryptionKey): string {
    return JSON.stringify({
      algorithm: key.algorithm,
      key: encodeBase64(key.key)
    })
  }

  static fromJSONString(str: string): EncryptionKey {
    const {
      key,
      algorithm
    }: { algorithm: EncryptionAlgorithm; key: string } = JSON.parse(str)

    return {
      algorithm,
      key: decodeBase64(key)
    }
  }

  // Base32 is useful as its not case sensitive, making it easy for a human to type in a secret key into their device
  static toBase32(encryptionKey: EncryptionKey): string {
    const key = base32
      .encode(encodeUTF8(encryptionKey.key))
      .toUpperCase()
      .replace(/(.{5})/g, "$1-")

    return `${ALGORITHM_TO_VERSION[encryptionKey.algorithm]}-${key}`
  }

  static fromBase32(base32Key: string): EncryptionKey {
    const [version, ...keyParts] = base32Key.replace(/\s+/g, "").split("-")
    const key = base32.decode(keyParts.join(""))
    return {
      key: decodeUTF8(key),
      algorithm: VERSION_TO_ALGORITHM[version]
    }
  }

  // Embedding an EncryptionKey in a QR code lets users scan them easily (nifty for copying your key to a new device)
  static toQRCode(encryptionKey: EncryptionKey, size: number): Promise<string> {
    return stringToQRCode(this.toJSONString(encryptionKey), size)
  }

  static fromQRCode(code: string): EncryptionKey {
    return this.fromJSONString(code)
  }
}

/** Encodes a string as an (svg) QR code */
function stringToQRCode(stringToEncode: string, size: number): Promise<string> {
  return new Promise((resolve, reject) => {
    QRCode.toString(
      stringToEncode,
      { type: "svg", errorCorrectionLevel: "H", width: size },
      (err: Error, svgString: string) => {
        if (err != null) {
          reject(err)
        } else {
          resolve(svgString)
        }
      }
    )
  })
}
