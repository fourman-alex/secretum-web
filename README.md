# Secretum Web

Deterministic passphrase generation from a FIDO2 hardware key — fully client-side.

## Description

Secretum Web is a web-based application that generates cryptographically secure, deterministic passphrases from your FIDO2 hardware security key. The same hardware key + same entry name will always produce the same passphrase on any machine, making it a portable password manager that requires no server or local storage.

### How It Works

1. You provide an entry name (e.g., `github.com`)
2. The app uses WebAuthn to authenticate with your FIDO2 hardware key
3. The key's PRF (Pseudo-Random Function) output is derived using HKDF-SHA256
4. A deterministic 64-character hexadecimal passphrase is generated
5. The passphrase is displayed for a limited time (auto-clears after 60 seconds)

**Security Model:**
- No passphrases, credentials, or keys are stored locally or on any server
- All cryptography happens in your browser using the Web Crypto API
- The relying party ID is bound to the origin, so the same setup works across machines
- No tracking, no analytics, no external dependencies

## Capabilities

- **Generate Passphrases**: Create deterministic passwords from hardware key + entry name
- **Register Keys**: First-time users automatically register their FIDO2 key (one-time per device)
- **Client-Side Only**: All operations run entirely in your browser
- **Fast Re-Auth**: Subsequent derivations require only one touch after initial registration
- **Auto-Clear**: Passphrases automatically clear from display after 60 seconds for security
- **Copy to Clipboard**: One-click copy of the generated passphrase
- **HTTPS Required**: Uses modern WebAuthn standards (Chrome 116+, compatible FIDO2 keys)

### Supported Hardware

- FIDO2 security keys with HMAC-secret support (e.g., Yubikey 5, Titan Security Key)
- Requires WebAuthn PRF extension support
- Browser: Chrome/Chromium 116+, Edge, and other Chromium-based browsers

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn
- A FIDO2 hardware security key (with PRF/HMAC-secret support)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd secretum-web

# Install dependencies
npm install
```

### Local Development

```bash
# Start the dev server (opens automatically at localhost:5173)
npm run dev
```

The application will be available at `http://localhost:5173`. Due to WebAuthn requirements, it must be served over `http://localhost` or `https://`.

### Build for Production

```bash
# Build and check TypeScript
npm run build
```

The optimized build will be output to the `dist/` directory.

### Preview Production Build

```bash
# Preview the production build locally
npm run preview
```

## Project Structure

```
.
├── app.ts              # Main application logic
├── app.css             # Tailwind CSS styles
├── index.html          # HTML entry point
├── vite.config.ts      # Vite configuration
├── tsconfig.json       # TypeScript configuration
├── package.json        # Dependencies and scripts
└── README.md           # This file
```

## Technology Stack

- **TypeScript**: Type-safe JavaScript
- **Vite**: Fast build tool and dev server
- **Tailwind CSS**: Utility-first CSS framework
- **Web Crypto API**: Browser's native cryptography
- **WebAuthn**: Hardware key authentication

## Browser Support

- Chrome/Chromium 116+
- Edge 116+
- Other Chromium-based browsers with WebAuthn support

## Security Considerations

- **HTTPS Required**: WebAuthn only works over HTTPS or localhost
- **No Backend Storage**: Nothing is stored on servers
- **Origin Bound**: Each origin produces different passphrases for the same entry
- **60-Second Auto-Clear**: Passphrases disappear from the UI after 60 seconds
- **No Logging**: No tracking or analytics

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "WebAuthn requires HTTPS" | Use `https://` or `http://localhost` |
| Key not recognized | Ensure your key supports FIDO2 with HMAC-secret (PRF) |
| PRF not supported | Upgrade your key or browser (requires Chrome 116+) |
| Passphrase not appearing | Try touching your key again when prompted |
