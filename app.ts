// Relying party ID — must match exactly between setup and derive.
// Bound to the origin, so same key + same entry = same passphrase on any machine.
const RP_ID = window.location.hostname || 'localhost';

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Generate random bytes using the Web Crypto API.
 * @param n - The number of random bytes to generate
 * @returns A Uint8Array containing random bytes
 */
function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/**
 * Convert an ArrayBuffer to a hexadecimal string.
 * @param buf - The ArrayBuffer to encode
 * @returns A lowercase hex string representation
 */
function hexEncode(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute the SHA-256 hash of a string.
 * @param str - The string to hash
 * @returns A Promise resolving to the SHA-256 hash as an ArrayBuffer
 */
async function sha256Bytes(str: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
}

/**
 * Compute the entry PRF input for HKDF-SHA256.
 * Mirrors the CLI's entryHMACSalt: sha256("secretum:entry:" + entry)
 * @param entry - The entry name
 * @returns A Promise resolving to the entry PRF input as an ArrayBuffer
 */
async function entryPRFInput(entry: string): Promise<ArrayBuffer> {
  return sha256Bytes('secretum:entry:' + entry);
}

// ── HKDF-SHA256 ───────────────────────────────────────────────────────────────

/**
 * Derive a 256-bit key using HKDF-SHA256.
 * Mirrors the CLI's kdf.Derive exactly:
 * - IKM  = PRF/hmac-secret output from the hardware key
 * - salt = SHA-256("secretum:kdf-salt:v1")
 * - info = "secretum-v1-passphrase:" + entry
 * - OKM  = 32 bytes → 64-char hex passphrase
 * @param ikmBuf - The input key material from the hardware device
 * @param entry - The entry name for info parameter
 * @returns A Promise resolving to the derived key material (256 bits)
 */
async function hkdfDerive(ikmBuf: BufferSource, entry: string): Promise<ArrayBuffer> {
  const hkdfSalt = await sha256Bytes('secretum:kdf-salt:v1');
  const ikm = await crypto.subtle.importKey(
    'raw', ikmBuf, { name: 'HKDF' }, false, ['deriveBits']
  );
  return crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: hkdfSalt,
      info: new TextEncoder().encode('secretum-v1-passphrase:' + entry),
    },
    ikm,
    256,
  );
}

// ── Register ──────────────────────────────────────────────────────────────────

/**
 * Create a resident key on the FIDO2 hardware device.
 * @returns A Promise that resolves when registration is complete
 */
async function register(): Promise<void> {
  setStatus('registerStatus', 'Touch your key when it blinks…', '');
  (btnRegister as HTMLButtonElement).disabled = true;

  let cred: Credential | null;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        challenge:        randomBytes(32).buffer,
        rp:               { id: RP_ID, name: 'Secretum Web' },
        user:             { id: randomBytes(32).buffer, name: 'secretum', displayName: 'Secretum' },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7   },  // ES256
          { type: 'public-key', alg: -257 },  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          residentKey:             'required',
          userVerification:        'preferred',
        },
        extensions: { prf: {} },
      },
    } as CredentialCreationOptions);
  } catch (e) {
    setStatus('registerStatus', `Registration failed: ${e instanceof Error ? e.message : String(e)}`, 'err');
    (btnRegister as HTMLButtonElement).disabled = false;
    return;
  }

  setStatus('registerStatus', 'Resident key created successfully.', 'ok');
  (btnRegister as HTMLButtonElement).disabled = false;
}

// ── Derive ────────────────────────────────────────────────────────────────────

/**
 * Derive a passphrase from a registered resident key.
 * Requires the key to be already registered (use the register function to create one).
 * Same key + same entry = same passphrase everywhere. Nothing stored locally.
 * @returns A Promise that resolves when derivation is complete
 */
async function derive(): Promise<void> {
  const entry = (document.getElementById('entryInput') as HTMLInputElement).value.trim();
  if (!entry) {
    setStatus('deriveStatus', 'Enter an entry name first.', 'err');
    (document.getElementById('entryInput') as HTMLInputElement).focus();
    return;
  }

  const prfInput = await entryPRFInput(entry);

  setStatus('deriveStatus', 'Touch your key when it blinks…', '');
  (btnDerive as HTMLButtonElement).disabled = true;
  hidePassphrase();

  // Get the credential from the registered resident key
  let prfFirst: ArrayBuffer | null = null;

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge:        randomBytes(32).buffer,
        rpId:             RP_ID,
        userVerification: 'preferred',
        extensions: { prf: { eval: { first: prfInput } } },
      },
    } as CredentialRequestOptions);

    if (!assertion || !(assertion instanceof PublicKeyCredential)) {
      throw new Error('Invalid credential type');
    }

    prfFirst = (assertion.getClientExtensionResults()?.prf?.results?.first ?? null) as ArrayBuffer | null;
  } catch (e) {
    setStatus('deriveStatus', `Derive failed: ${e instanceof Error ? e.message : String(e)}. Make sure you've created a resident key first.`, 'err');
    (btnDerive as HTMLButtonElement).disabled = false;
    return;
  }

  if (!prfFirst) {
    setStatus(
      'deriveStatus',
      'PRF result not returned. Ensure both the key and browser support the PRF/hmac-secret extension.',
      'err',
    );
    (btnDerive as HTMLButtonElement).disabled = false;
    return;
  }

  const passphrase = hexEncode(await hkdfDerive(prfFirst, entry));
  showPassphrase(passphrase);
  setStatus('deriveStatus', '', '');
  (btnDerive as HTMLButtonElement).disabled = false;
}

// ── Passphrase display + auto-clear timer ─────────────────────────────────────

const CLEAR_AFTER_SECS = 60;
let clearTimer: ReturnType<typeof setInterval> | null = null;

/**
 * Display the passphrase in the UI and start the auto-clear timer.
 * @param hex - The passphrase as a hexadecimal string
 */
function showPassphrase(hex: string): void {
  (document.getElementById('passphraseValue') as HTMLElement).textContent = hex;
  (document.getElementById('passphraseBox') as HTMLElement).style.display = 'block';
  startClearTimer();
}

/**
 * Hide the passphrase from the UI and stop the auto-clear timer.
 */
function hidePassphrase(): void {
  (document.getElementById('passphraseBox') as HTMLElement).style.display = 'none';
  (document.getElementById('passphraseValue') as HTMLElement).textContent = '';
  stopClearTimer();
}

/**
 * Start the auto-clear timer and update the countdown display.
 */
function startClearTimer(): void {
  stopClearTimer();
  let remaining = CLEAR_AFTER_SECS;
  const secsEl  = document.getElementById('timerSecs') as HTMLElement;
  const labelEl = document.getElementById('timerLabel') as HTMLElement;
  secsEl.textContent = remaining.toString();
  clearTimer = setInterval(() => {
    remaining -= 1;
    secsEl.textContent = remaining.toString();
    labelEl.textContent = `Clears in ${remaining}s`;
    if (remaining <= 0) hidePassphrase();
  }, 1000);
}

/**
 * Stop the auto-clear timer and clear the countdown display.
 */
function stopClearTimer(): void {
  if (clearTimer) { clearInterval(clearTimer); clearTimer = null; }
  (document.getElementById('timerLabel') as HTMLElement).textContent = '';
}

// ── UI helpers ────────────────────────────────────────────────────────────────

/**
 * Set the status message and styling for a UI element.
 * @param id - The element ID to update
 * @param msg - The status message to display
 * @param type - The message type: 'ok', 'err', or '' (default)
 */
function setStatus(id: string, msg: string, type: string): void {
  const el = document.getElementById(id) as HTMLElement;
  el.textContent = msg;
  const colorClass = type === 'ok' ? 'text-success' : type === 'err' ? 'text-danger' : 'text-primary/60';
  el.className = `text-[0.8125rem] min-h-[1.2em] mt-3 ${colorClass}`;
}

// ── Wiring ────────────────────────────────────────────────────────────────────

const btnRegister = document.getElementById('btnRegister') as HTMLButtonElement;
const btnDerive   = document.getElementById('btnDerive') as HTMLButtonElement;
const btnCopy     = document.getElementById('btnCopy') as HTMLButtonElement;

btnRegister.addEventListener('click', register);
btnDerive.addEventListener('click', derive);

(document.getElementById('entryInput') as HTMLInputElement).addEventListener('keydown', (e: KeyboardEvent) => {
  if (e.key === 'Enter') derive();
});

btnCopy.addEventListener('click', async () => {
  const val = (document.getElementById('passphraseValue') as HTMLElement).textContent || '';
  await navigator.clipboard.writeText(val);
  btnCopy.textContent = 'Copied!';
  setTimeout(() => { btnCopy.textContent = 'Copy'; }, 2000);
});

// Warn if not on a secure origin (WebAuthn won't work).
if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
  (document.getElementById('httpsWarning') as HTMLElement).style.display = 'block';
}
