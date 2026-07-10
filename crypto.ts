// Secretum Web – passphrase encryption / decryption helpers.
//
// Encryption:
//   1. Generate a random 256-bit DEK (AES-GCM).
//   2. Encrypt the user's passphrase with the DEK.
//   3. For each hardware key: call WebAuthn PRF, derive a KEK (HKDF-SHA256),
//      and wrap the DEK with AES-KW.
//   4. Assemble a minimal JSON blob and download it.
//
// Decryption:
//   1. Load the JSON blob.
//   2. Touch the hardware key → PRF → re-derive KEK → unwrap DEK → decrypt.
//
// Encrypted file format:
//   iv          = base64url(12B)
//   recipients  = [ { kid:<b64u credId>, prf_nonce:<b64u 32B>,
//                      encrypted_key:<b64u AES-KW(DEK)> } ]
//   ciphertext  = base64url(AES-GCM ciphertext)

// ── Base64url ──────────────────────────────────────────────────────────────────

/**
 * Encode a byte array to a base64url string (no padding).
 * @param input - The bytes to encode.
 * @returns A base64url-encoded string.
 */
export function b64uEncode(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decode a base64url string (with or without padding) back to bytes.
 * @param s - The base64url-encoded string.
 * @returns The decoded byte array.
 */
export function b64uDecode(s: string): Uint8Array<ArrayBuffer> {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(s.padEnd(s.length + (4 - (s.length % 4)) % 4, '='));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────

/**
 * Generate `n` cryptographically secure random bytes.
 * @param n - Number of bytes to generate.
 * @returns A random byte array.
 */
export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/**
 * Compute the SHA-256 digest of a UTF-8 string.
 * @param msg - The string to hash.
 * @returns The 32-byte SHA-256 digest.
 */
export async function sha256(msg: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
}

/**
 * Derive the deterministic PRF input for a given per-recipient nonce.
 * The same nonce during decryption reproduces the same PRF input.
 * @param nonce - The 32-byte recipient nonce.
 * @returns The PRF input digest.
 */
export async function prfInputFor(nonce: Uint8Array): Promise<ArrayBuffer> {
  return sha256('secretum:jwe-v1:wrap:' + b64uEncode(nonce));
}

/**
 * Derive a 256-bit AES-KW key encryption key (KEK) from a PRF output using HKDF-SHA256.
 * @param prfOutput - The PRF result from a WebAuthn authenticator.
 * @returns A CryptoKey suitable for AES-KW wrap/unwrap operations.
 */
export async function deriveKEK(prfOutput: ArrayBuffer): Promise<CryptoKey> {
  const hkdfSalt = await sha256('secretum:jwe-kek-salt:v1');
  const ikm = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: hkdfSalt,
      info: new TextEncoder().encode('secretum-jwe-v1-kek'),
    },
    ikm,
    256,
  );
  return crypto.subtle.importKey('raw', bits, 'AES-KW', false, ['wrapKey', 'unwrapKey']);
}

// ── Encrypted file types ───────────────────────────────────────────────────────

/** Per-recipient identifying the credential and wrapped DEK. */
export interface Recipient {
  /** base64url-encoded credential ID. */
  kid: string;
  /** base64url-encoded 32-byte PRF nonce, unique per encryption. */
  prf_nonce: string;
  /** base64url-encoded AES-KW wrapped DEK. */
  encrypted_key: string;
}

/** Minimal encrypted file format used by Secretum. */
export interface EncryptedFile {
  iv:         string; // base64url(12B)
  recipients: Recipient[];
  ciphertext: string; // base64url(AES-GCM ciphertext bytes)
}

/** A hardware key known to the application, with its wrapped DEK recipient. */
export interface StoredKey {
  credentialId: ArrayBuffer;
  /** Short display label derived from the credential ID. */
  label: string;
  /** DEK wrapped for this key. */
  recipient: Recipient;
}

// ── DEK management ─────────────────────────────────────────────────────────────

/**
 * Generate a random 256-bit AES-GCM data encryption key (DEK).
 * @returns A new extractable AES-GCM CryptoKey.
 */
export async function generateDEK(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

/** Result of wrapping a DEK for a single hardware key. */
export interface WrappedKey {
  /** base64url-encoded credential ID returned by WebAuthn. */
  kid: string;
  recipient: Recipient;
}

/**
 * Wrap the DEK for a specific hardware key using WebAuthn PRF + AES-KW.
 * @param dek - The data encryption key to wrap.
 * @param credentialId - The credential ID of the target hardware key.
 * @param prfNonce - A unique 32-byte nonce for this recipient.
 * @returns The wrapped key metadata and recipient block.
 * @throws If the authenticator does not support the PRF extension.
 */
export async function wrapDEKForKey(dek: CryptoKey, credentialId: ArrayBuffer, prfNonce: Uint8Array): Promise<WrappedKey> {
  const prfInput = await prfInputFor(prfNonce);
  const allowCreds = [{ type: 'public-key' as const, id: new Uint8Array(credentialId) }];

  const raw = await navigator.credentials.get({
    publicKey: {
      challenge:        randomBytes(32).buffer,
      rpId:             window.location.hostname || 'localhost',
      userVerification: 'preferred',
      allowCredentials: allowCreds,
      extensions:       { prf: { eval: { first: prfInput } } },
    },
  } as CredentialRequestOptions);

  if (!raw || !(raw instanceof PublicKeyCredential)) throw new Error('Unexpected credential type.');

  const ext = raw.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  if (!ext.prf?.results?.first) {
    throw new Error(
      'Key does not support the PRF extension. Use a PRF-capable key (e.g. YubiKey 5) with Chrome 116+.',
    );
  }

  const resultKid = b64uEncode(new Uint8Array(raw.rawId));
  const kek = await deriveKEK(ext.prf.results.first);
  const wrappedDEK = await crypto.subtle.wrapKey('raw', dek, kek, 'AES-KW');

  const recipient: Recipient = {
    kid: resultKid,
    prf_nonce: b64uEncode(prfNonce),
    encrypted_key: b64uEncode(wrappedDEK),
  };

  return { kid: resultKid, recipient };
}

/** Inputs needed for a WebAuthn `navigator.credentials.get` PRF extension call. */
export interface PRFInputs {
  allowCreds: { type: 'public-key'; id: Uint8Array }[];
  prfExt: { eval?: { first: ArrayBuffer } } | { evalByCredential?: Record<string, { first: ArrayBuffer }> };
}

/**
 * Build allowCredentials and PRF extension inputs from an encrypted file's recipients.
 * Uses single `eval` for one recipient, or `evalByCredential` for many.
 * @param file - The encrypted file to decrypt.
 * @returns The WebAuthn PRF inputs.
 */
export async function buildPRFInputs(file: EncryptedFile): Promise<PRFInputs> {
  const allowCreds: { type: 'public-key'; id: Uint8Array }[] = [];
  const evalByCred: Record<string, { first: ArrayBuffer }> = {};

  for (const r of file.recipients) {
    allowCreds.push({ type: 'public-key', id: b64uDecode(r.kid) });
    evalByCred[r.kid] = { first: await prfInputFor(b64uDecode(r.prf_nonce)) };
  }

  const prfExt = file.recipients.length === 1
    ? { eval: evalByCred[file.recipients[0].kid] }
    : { evalByCredential: evalByCred };

  return { allowCreds, prfExt };
}

/** Result of successfully decrypting an encrypted file. */
export interface DecryptResult {
  plaintext: string;
}

/**
 * Decrypt an encrypted file by prompting the user to touch a recipient hardware key.
 * @param file - The encrypted file to decrypt.
 * @returns The decrypted plaintext.
 * @throws If the credential is invalid, PRF is unsupported, or decryption fails.
 */
export async function decryptEncryptedFile(file: EncryptedFile): Promise<DecryptResult> {
  const rpId = window.location.hostname || 'localhost';
  const { allowCreds, prfExt } = await buildPRFInputs(file);

  const raw = await navigator.credentials.get({
    publicKey: {
      challenge:        randomBytes(32).buffer,
      rpId,
      userVerification: 'preferred',
      allowCredentials: allowCreds,
      extensions:       { prf: prfExt } as AuthenticationExtensionsClientInputs,
    },
  } as CredentialRequestOptions);

  if (!raw || !(raw instanceof PublicKeyCredential)) throw new Error('Invalid credential.');

  const prfOutput = ((raw.getClientExtensionResults() as any)?.prf?.results?.first) as ArrayBuffer | null;
  if (!prfOutput) {
    throw new Error('PRF not returned. Ensure your key and browser support the PRF extension (Chrome 116+).');
  }

  const usedKid = b64uEncode(new Uint8Array(raw.rawId));
  const recipient = file.recipients.find(r => r.kid === usedKid);
  if (!recipient) throw new Error('The used key is not a recipient of this file.');

  const kek = await deriveKEK(prfOutput);
  const dek = await crypto.subtle.unwrapKey(
    'raw',
    b64uDecode(recipient.encrypted_key),
    kek,
    'AES-KW',
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  const ctWithTag = b64uDecode(file.ciphertext);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64uDecode(file.iv), tagLength: 128 },
    dek,
    ctWithTag,
  );

  return { plaintext: new TextDecoder().decode(plaintext) };
}

// ── Encrypted file assembly / validation ───────────────────────────────────────

/**
 * Validate that a value matches the required encrypted file shape.
 * @param file - The value to validate.
 * @returns The validated encrypted file object.
 * @throws If required fields are missing or malformed.
 */
export function validateEncryptedFile(file: unknown): EncryptedFile {
  if (!file || typeof file !== 'object') {
    throw new Error('Encrypted file must be an object.');
  }
  const f = file as Record<string, unknown>;
  if (
    typeof f.iv !== 'string' ||
    !Array.isArray(f.recipients) ||
    typeof f.ciphertext !== 'string'
  ) {
    throw new Error('Missing required encrypted file fields.');
  }
  return file as EncryptedFile;
}

/**
 * Build an encrypted file object by encrypting a passphrase with AES-GCM.
 * @param passphrase - The plaintext passphrase to encrypt.
 * @param recipients - Recipient blocks containing the AES-KW wrapped DEKs.
 * @param dek - The data encryption key used for AES-GCM encryption.
 * @returns The assembled encrypted file object.
 */
export async function buildEncryptedFile(
  passphrase: string,
  recipients: Recipient[],
  dek: CryptoKey,
): Promise<EncryptedFile> {
  const iv = randomBytes(12);

  const ctWithTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    dek,
    new TextEncoder().encode(passphrase),
  ));

  return {
    iv:         b64uEncode(iv),
    recipients,
    ciphertext: b64uEncode(ctWithTag),
  };
}
