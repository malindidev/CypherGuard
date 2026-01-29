# CypherGuard

CypherGuard is a browser-based client-side encryption and decryption tool using **AES-GCM** with keys derived from passphrases via **PBKDF2**. It allows users to securely encrypt messages, decrypt them, and optionally generate or scan QR codes for encrypted payloads.

---

## Features

- **AES-GCM 256-bit encryption** for secure message confidentiality.
- **PBKDF2 key derivation** with 100,000 iterations for robust passphrase security.
- **Encrypt and Decrypt messages** entirely in the browser – no server-side processing.
- **Copy results** to clipboard with one click.
- **Clear input and output** easily.
- **QR Code support**:
  - Generate a QR code for the encrypted message.
  - Download the QR code as a PNG.
  - Upload and scan a QR code to retrieve encrypted content.
- Fully **client-side**, works offline after page load.
- Accessible design with `aria` attributes for screen readers.

---

## Demo

> ⚠️ Always use HTTPS when using encryption tools in production for security.
> **https://cg.bbnerds.com**

---

## Usage

1. Enter a message in the **Message** field.
2. Enter a passphrase (minimum 6 characters) in the **Passphrase** field.
3. Click **Encrypt** to generate the encrypted Base64 payload.
4. Click **Decrypt** to decrypt a Base64 payload back to plaintext.
5. Optional:
   - Click **Copy** to copy the result to the clipboard.
   - Click **Clear** to reset the fields.
   - Click **QR** to generate a QR code from the result.
   - Click **Download QR** to save the QR code as an image.
   - Click **Upload QR** to load an encrypted payload from a QR code image.

---

## Installation

Clone or download the repository:

```bash
git clone https://github.com/malindidev/cypherguard.git
cd cypherguard
