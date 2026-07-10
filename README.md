# Secretum Web

Passphrase encryption with multiple FIDO2 hardware keys — fully client-side.

## Description

Secretum Web encrypts an arbitrary passphrase (or any secret text) using your FIDO2 hardware security key and produces a compact **JSON** file. Multiple hardware keys can be enrolled so that any one of them can independently decrypt the file. All cryptography runs in the browser using the Web Crypto API — nothing is sent to any server.

### How It Works

**Encryption**
1. A random 256-bit **Data Encryption Key (DEK)** is generated.
2. The passphrase is encrypted with the DEK using **AES-256-GCM**.
3. For each enrolled hardware key:
   - WebAuthn's **PRF extension** (`hmac-secret`) is invoked with a unique random nonce.
   - The PRF output is stretched into a **Key Encryption Key (KEK)** via **HKDF-SHA-256**.
   - The DEK is **wrapped** with the KEK using **AES-KW**.
4. A compact **JSON file** is assembled and downloaded.

**Decryption**
1. Load the encrypted JSON file (file upload or paste).
2. Touch any enrolled hardware key → PRF output → re-derive KEK → **unwrap DEK** → **decrypt** passphrase.
3. The decrypted passphrase is displayed and auto-clears after 60 seconds.

**Security Model**
- No passphrase, key material, or encrypted file content is ever stored locally or transmitted to a server.
- All cryptography is performed in the browser (Web Crypto API).
- The auto-clear timer limits the passphrase exposure window to 60 seconds.

## Getting Started

### Prerequisites

- Node.js 18+
- A PRF-capable FIDO2 hardware key (e.g. YubiKey 5 series)
- Chrome / Chromium 116+ (required for WebAuthn PRF extension)

### Installation

```bash
git clone <repository-url>
cd secretum-web
npm install
```

### Local Development

```bash
npm run dev          # dev server at http://localhost:5173
```

### Build for Production

```bash
npm run build        # outputs to dist/
npm run preview      # preview the production build
```

## Usage

### Encrypting a Passphrase

1. **Register** (first time only): expand *"First time?"* and click **Register Key** to create a resident credential on your hardware device.
2. Go to the **Encrypt** tab.
3. Enter the passphrase you want to protect.
4. Click **+ Add Key** and touch your hardware key. Repeat for additional keys.
6. Click **Encrypt & Download** — touch each listed key once when prompted.
7. Save the downloaded `passphrase.secretum.json`.

### Decrypting a Passphrase

1. Go to the **Decrypt** tab.
2. Drop or browse to your `.secretum.json` file, or paste the JSON directly.
3. Click **Decrypt** and touch any enrolled hardware key.
4. The passphrase is shown and auto-clears after 60 seconds.

## Encrypted File Format

```json
{
  "iv": "<base64url(12B)>",
  "recipients": [
    {
      "kid": "<base64url(credentialId)>",
      "prf_nonce": "<base64url(32 random bytes)>",
      "encrypted_key": "<base64url(AES-KW wrapped DEK)>"
    }
  ],
  "ciphertext": "<base64url(AES-GCM ciphertext + 16B tag)>"
}
```

## Project Structure

```
app.ts          Main application logic (crypto + UI)
app.css         Tailwind CSS styles
index.html      HTML entry point
vite.config.ts  Vite + Tailwind configuration
tsconfig.json   TypeScript configuration
package.json    Dependencies and scripts
```

## Technology Stack

- **TypeScript** · **Vite** · **Tailwind CSS v4**
- **Web Crypto API** — AES-GCM, AES-KW, HKDF-SHA-256
- **WebAuthn PRF extension** (`hmac-secret`) via `navigator.credentials`

## Browser Support

| Browser | Version |
|---------|---------|
| Chrome / Chromium | 116+ |
| Edge | 116+ |

Firefox does not currently support the WebAuthn PRF extension.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "WebAuthn requires HTTPS" | Use `https://` or `http://localhost` |
| PRF not returned | Upgrade to Chrome 116+ and use a PRF-capable key |
| Decryption failed | Ensure you are using one of the keys that was enrolled during encryption |
| Key not found | Register the key first via *"First time?"* in the Encrypt tab |
