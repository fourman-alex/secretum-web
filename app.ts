// Relying party ID — must match exactly between setup and derive.
// Bound to the origin, so same key + same entry = same passphrase on any machine.
const RP_ID = window.location.hostname || 'localhost';

// ── Helpers ───────────────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function hexEncode(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Bytes(str: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
}

// Mirrors the CLI's entryHMACSalt: sha256("secretum:entry:" + entry)
async function entryPRFInput(entry: string): Promise<ArrayBuffer> {
  return sha256Bytes('secretum:entry:' + entry);
}

// ── HKDF-SHA256 ───────────────────────────────────────────────────────────────
// Mirrors the CLI's kdf.Derive exactly:
//   IKM  = PRF/hmac-secret output from the hardware key
//   salt = SHA-256("secretum:kdf-salt:v1")
//   info = "secretum-v1-passphrase:" + entry
//   OKM  = 32 bytes → 64-char hex passphrase

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

// ── Setup ─────────────────────────────────────────────────────────────────────
// Registers a resident credential with PRF enabled. Nothing is saved locally —
// the credential lives entirely on the key, discovered by RP_ID at derive time.
// Run once per key per origin (mirrors `secretum setup`).

async function setup(): Promise<void> {
  const userId    = randomBytes(32);
  const challenge = randomBytes(32);

  setStatus('setupStatus', 'Touch your key when it blinks…', '');

  let cred: Credential | null;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        challenge:              challenge.buffer,
        rp:                     { id: RP_ID, name: 'Secretum Web' },
        user:                   { id: userId.buffer, name: 'secretum', displayName: 'Secretum' },
        pubKeyCredParams:       [
          { type: 'public-key', alg: -7   },  // ES256
          { type: 'public-key', alg: -257 },  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform', // hardware key only
          residentKey:             'required',        // discoverable — mirrors CLI's RK: true
          userVerification:        'preferred',
        },
        extensions: { prf: {} },
      },
    } as CredentialCreationOptions);
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    setStatus('setupStatus', `Setup failed: ${error}`, 'err');
    return;
  }

  const publicKeyCredential = cred as PublicKeyCredential;
  if (!publicKeyCredential.getClientExtensionResults()?.prf?.enabled) {
    setStatus(
      'setupStatus',
      'PRF extension not supported by this key or browser. Requires Chrome 116+ and a FIDO2 key with hmac-secret.',
      'err',
    );
    return;
  }

  setStatus('setupStatus', `Credential registered for "${RP_ID}". You can now derive passphrases on any machine.`, 'ok');
}

// ── Derive ────────────────────────────────────────────────────────────────────
// No credential ID needed — the key discovers its own resident credential for
// RP_ID, exactly as the CLI does with an empty credential list.
// Same key + same entry = same passphrase everywhere.

async function derive(): Promise<void> {
  const entry = (document.getElementById('entryInput') as HTMLInputElement).value.trim();
  if (!entry) {
    setStatus('deriveStatus', 'Enter an entry name first.', 'err');
    (document.getElementById('entryInput') as HTMLInputElement).focus();
    return;
  }

  const prfInput  = await entryPRFInput(entry);
  const challenge = randomBytes(32);

  setStatus('deriveStatus', 'Touch your key when it blinks…', '');
  (btnDerive as HTMLButtonElement).disabled = true;
  hidePassphrase();

  let assertion: Credential | null;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge:        challenge.buffer,
        rpId:             RP_ID,
        // No allowCredentials — key discovers its resident credential by RP_ID,
        // just like the CLI passes an empty credential list.
        userVerification: 'preferred',
        extensions: {
          prf: { eval: { first: prfInput } },
        },
      },
    } as CredentialRequestOptions);
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    setStatus('deriveStatus', `Derivation failed: ${error}`, 'err');
    (btnDerive as HTMLButtonElement).disabled = false;
    return;
  }

  const publicKeyCredential = assertion as PublicKeyCredential;
  const prfFirst = publicKeyCredential.getClientExtensionResults()?.prf?.results?.first;
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

function showPassphrase(hex: string): void {
  (document.getElementById('passphraseValue') as HTMLElement).textContent = hex;
  (document.getElementById('passphraseBox') as HTMLElement).style.display = 'block';
  startClearTimer();
}

function hidePassphrase(): void {
  (document.getElementById('passphraseBox') as HTMLElement).style.display = 'none';
  (document.getElementById('passphraseValue') as HTMLElement).textContent = '';
  stopClearTimer();
}

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

function stopClearTimer(): void {
  if (clearTimer) { clearInterval(clearTimer); clearTimer = null; }
  (document.getElementById('timerLabel') as HTMLElement).textContent = '';
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function setStatus(id: string, msg: string, type: string): void {
  const el = document.getElementById(id) as HTMLElement;
  el.textContent = msg;
  const colorClass = type === 'ok' ? 'text-success' : type === 'err' ? 'text-danger' : 'text-primary/60';
  el.className = `text-[0.8125rem] min-h-[1.2em] mt-3 ${colorClass}`;
}

// ── Wiring ────────────────────────────────────────────────────────────────────

const btnSetup  = document.getElementById('btnSetup') as HTMLButtonElement;
const btnDerive = document.getElementById('btnDerive') as HTMLButtonElement;
const btnCopy   = document.getElementById('btnCopy') as HTMLButtonElement;

btnSetup.addEventListener('click', setup);
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
