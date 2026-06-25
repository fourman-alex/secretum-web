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

// ── Derive ────────────────────────────────────────────────────────────────────
// Mirrors the CLI's derive command: tries get first; if no credential exists
// for this RP_ID, registers one (with PRF eval at create time when supported),
// then falls back to a second get if the key didn't return PRF during create.
// Same key + same entry = same passphrase everywhere. Nothing stored locally.

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

  // ── 1. Fast path: key already registered ──────────────────────────────────
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

    prfFirst = ((assertion as PublicKeyCredential)
      .getClientExtensionResults()?.prf?.results?.first ?? null) as ArrayBuffer | null;
  } catch {
    // No credential yet — fall through to register.
  }

  // ── 2. First-run path: register, then get PRF ──────────────────────────────
  if (!prfFirst) {
    setStatus('deriveStatus', 'No key registered — registering now. Touch your key when it blinks…', '');

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
          // Request PRF at creation time — some keys return it immediately,
          // saving a second touch. Others ignore it; we fall back below.
          extensions: { prf: { eval: { first: prfInput } } },
        },
      } as CredentialCreationOptions);
    } catch (e) {
      setStatus('deriveStatus', `Registration failed: ${e instanceof Error ? e.message : String(e)}`, 'err');
      (btnDerive as HTMLButtonElement).disabled = false;
      return;
    }

    const pk  = cred as PublicKeyCredential;
    const ext = pk.getClientExtensionResults();

    if (!ext?.prf?.enabled) {
      setStatus(
        'deriveStatus',
        'PRF extension not supported by this key or browser. Requires Chrome 116+ and a FIDO2 key with hmac-secret.',
        'err',
      );
      (btnDerive as HTMLButtonElement).disabled = false;
      return;
    }

    // Some keys return PRF during create — use it directly (one touch total).
    prfFirst = (ext?.prf?.results?.first ?? null) as ArrayBuffer | null;

    if (!prfFirst) {
      // Most keys require a separate assertion after registration — touch again.
      setStatus('deriveStatus', 'Key registered. Touch again to derive your passphrase…', '');
      try {
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge:        randomBytes(32).buffer,
            rpId:             RP_ID,
            userVerification: 'preferred',
            extensions: { prf: { eval: { first: prfInput } } },
          },
        } as CredentialRequestOptions);

        prfFirst = ((assertion as PublicKeyCredential)
          .getClientExtensionResults()?.prf?.results?.first ?? null) as ArrayBuffer | null;
      } catch (e) {
        setStatus('deriveStatus', `Derivation failed: ${e instanceof Error ? e.message : String(e)}`, 'err');
        (btnDerive as HTMLButtonElement).disabled = false;
        return;
      }
    }
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

const btnDerive = document.getElementById('btnDerive') as HTMLButtonElement;
const btnCopy   = document.getElementById('btnCopy') as HTMLButtonElement;

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
