// Secretum Web – UI wiring for passphrase encryption / decryption with FIDO2 hardware keys.
import {
  b64uEncode,
  randomBytes,
  prfInputFor,
  deriveKEK,
  generateDEK,
  buildEncryptedFile,
  validateEncryptedFile,
  decryptEncryptedFile,
  type EncryptedFile,
  type Recipient,
  type StoredKey,
} from './crypto.js';

const RP_ID = window.location.hostname || 'localhost';

// Static user handle for the project's single logical user. Keeping this stable
// prevents creating duplicate resident keys every time registration is run.
const USER_ID = new Uint8Array([0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x75, 0x6d]); // "secretum"

// ── State ──────────────────────────────────────────────────────────────────────

const storedKeys: StoredKey[] = [];
let dek: CryptoKey | null = null;
let importedFile: EncryptedFile | null = null;
let decryptClearTimer: ReturnType<typeof setInterval> | null = null;

// ── DOM refs ───────────────────────────────────────────────────────────────────

const panelEncrypt   = document.getElementById('panelEncrypt')      as HTMLElement;
const panelDecrypt   = document.getElementById('panelDecrypt')      as HTMLElement;
const tabEncryptBtn  = document.getElementById('tabEncrypt')        as HTMLButtonElement;
const tabDecryptBtn  = document.getElementById('tabDecrypt')        as HTMLButtonElement;
const keyListEl      = document.getElementById('keyList')           as HTMLElement;
const btnAddKey      = document.getElementById('btnAddKey')         as HTMLButtonElement;
const btnEncrypt     = document.getElementById('btnEncrypt')        as HTMLButtonElement;
const encryptStatusEl = document.getElementById('encryptStatus')   as HTMLElement;
const btnRegister    = document.getElementById('btnRegister')       as HTMLButtonElement;
const registerStatusEl = document.getElementById('registerStatus') as HTMLElement;
const fileInput      = document.getElementById('fileInput')         as HTMLInputElement;
const dropZone       = document.getElementById('dropZone')          as HTMLElement;
const fileTextarea   = document.getElementById('fileTextarea')      as HTMLTextAreaElement;
const fileInfoEl     = document.getElementById('fileInfo')          as HTMLElement;
const btnDecrypt     = document.getElementById('btnDecrypt')        as HTMLButtonElement;
const decryptStatusEl = document.getElementById('decryptStatus')   as HTMLElement;
const decryptResultEl = document.getElementById('decryptResult')   as HTMLElement;
const decryptValueEl  = document.getElementById('decryptValue')    as HTMLElement;
const decryptSecsEl   = document.getElementById('decryptTimerSecs') as HTMLElement;
const decryptLabelEl  = document.getElementById('decryptTimerLabel') as HTMLElement;
const btnDecryptCopy  = document.getElementById('btnDecryptCopy')  as HTMLButtonElement;

// ── UI helpers ─────────────────────────────────────────────────────────────────

function setEncStatus(msg: string, type: '' | 'ok' | 'err'): void {
  encryptStatusEl.textContent = msg;
  encryptStatusEl.className = `text-[0.8125rem] min-h-[1.2em] mt-3 ${
    type === 'ok' ? 'text-success' : type === 'err' ? 'text-danger' : 'text-primary/60'
  }`;
}

function setDecStatus(msg: string, type: '' | 'ok' | 'err'): void {
  decryptStatusEl.textContent = msg;
  decryptStatusEl.className = `text-[0.8125rem] min-h-[1.2em] mt-3 ${
    type === 'ok' ? 'text-success' : type === 'err' ? 'text-danger' : 'text-primary/60'
  }`;
}

function setRegStatus(msg: string, type: '' | 'ok' | 'err'): void {
  registerStatusEl.textContent = msg;
  registerStatusEl.className = `text-[0.8125rem] min-h-[1.2em] mt-3 ${
    type === 'ok' ? 'text-success' : type === 'err' ? 'text-danger' : 'text-primary/60'
  }`;
}

// ── Tab switching ──────────────────────────────────────────────────────────────

const TAB_ACTIVE   = 'flex-1 py-1.5 rounded-md text-sm font-semibold transition-colors duration-120 bg-secondary text-primary';
const TAB_INACTIVE = 'flex-1 py-1.5 rounded-md text-sm font-semibold transition-colors duration-120 text-secondary';

async function ensureDEK(): Promise<void> {
  if (dek) return;
  dek = await generateDEK();
}

function switchTab(tab: 'encrypt' | 'decrypt'): void {
  const enc = tab === 'encrypt';
  panelEncrypt.style.display = enc ? '' : 'none';
  panelDecrypt.style.display = enc ? 'none' : '';
  tabEncryptBtn.className    = enc ? TAB_ACTIVE   : TAB_INACTIVE;
  tabDecryptBtn.className    = enc ? TAB_INACTIVE : TAB_ACTIVE;

  if (enc) {
    ensureDEK();
  }
}

tabEncryptBtn.addEventListener('click', () => switchTab('encrypt'));
tabDecryptBtn.addEventListener('click', () => switchTab('decrypt'));

// ── Register (one-time setup) ──────────────────────────────────────────────────

btnRegister.addEventListener('click', async () => {
  btnRegister.disabled = true;
  setRegStatus('Touch your key when it blinks…', '');
  try {
    await navigator.credentials.create({
      publicKey: {
        challenge:        randomBytes(32).buffer,
        rp:               { id: RP_ID, name: 'Secretum Web' },
        user:             { id: USER_ID, name: 'secretum', displayName: 'Secretum' },
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
    setRegStatus('Resident key created. You can now click "Add Key" above.', 'ok');
  } catch (e) {
    setRegStatus(`Registration failed: ${e instanceof Error ? e.message : String(e)}`, 'err');
  } finally {
    btnRegister.disabled = false;
  }
});

// ── Encrypt panel: key management ─────────────────────────────────────────────

function renderKeyList(): void {
  keyListEl.innerHTML = '';
  if (storedKeys.length === 0) {
    const p = document.createElement('p');
    p.className = 'text-[0.8125rem] text-secondary';
    p.textContent = 'No keys added yet. Add at least one hardware key to enable encryption.';
    keyListEl.appendChild(p);
    btnEncrypt.disabled = true;
    return;
  }

  const ul = document.createElement('ul');
  ul.className = 'space-y-2';

  storedKeys.forEach((k, i) => {
    const li = document.createElement('li');
    li.className = 'flex items-center justify-between bg-white/5 rounded-md px-3 py-2';

    const span = document.createElement('span');
    span.className = 'font-mono text-[0.8125rem] text-secondary';
    span.textContent = k.label;

    const btn = document.createElement('button');
    btn.className = 'text-xs text-danger hover:underline cursor-pointer ml-3 shrink-0';
    btn.textContent = 'Remove';
    btn.addEventListener('click', () => { storedKeys.splice(i, 1); renderKeyList(); });

    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  });

  keyListEl.appendChild(ul);
  btnEncrypt.disabled = false;
}

btnAddKey.addEventListener('click', async () => {
  btnAddKey.disabled = true;
  setEncStatus('Touch your hardware key…', '');
  try {
    await ensureDEK();
    if (!dek) throw new Error('DEK not ready.');

    const prfNonce = randomBytes(32);
    const prfInput = await prfInputFor(prfNonce);

    const raw = await navigator.credentials.get({
      publicKey: {
        challenge:        randomBytes(32).buffer,
        rpId:             RP_ID,
        userVerification: 'preferred',
        extensions:       { prf: { eval: { first: prfInput } } },
      },
    } as CredentialRequestOptions);

    if (!raw || !(raw instanceof PublicKeyCredential)) throw new Error('Unexpected credential type.');

    const ext = raw.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
    if (!ext.prf?.results?.first) {
      throw new Error(
        'Key did not return PRF results. Use a PRF-capable key.',
      );
    }

    const kid = b64uEncode(raw.rawId);
    if (storedKeys.some(k => b64uEncode(k.credentialId) === kid)) {
      setEncStatus('This key is already in the list.', 'err');
      return;
    }

    const kek = await deriveKEK(ext.prf.results.first);
    const wrappedDEK = await crypto.subtle.wrapKey('raw', dek, kek, 'AES-KW');

    const recipient: Recipient = {
      kid,
      prf_nonce: b64uEncode(prfNonce),
      encrypted_key: b64uEncode(wrappedDEK),
    };

    const label = `···${kid.slice(-12)}`;
    storedKeys.push({ credentialId: raw.rawId, label, recipient });
    renderKeyList();
    setEncStatus(`Key added (${label}).`, 'ok');
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    setEncStatus(`Could not add key: ${msg}`, 'err');
  } finally {
    btnAddKey.disabled = false;
  }
});

// ── Encrypt & Download ─────────────────────────────────────────────────────────

btnEncrypt.addEventListener('click', async () => {
  const passphrase = (document.getElementById('passphraseInput') as HTMLTextAreaElement).value;

  if (!passphrase) { setEncStatus('Enter a passphrase to encrypt.', 'err'); return; }

  if (!dek || storedKeys.length === 0) {
    setEncStatus('Add at least one hardware key before encrypting.', 'err');
    return;
  }

  btnEncrypt.disabled = true;
  btnAddKey.disabled  = true;

  try {
    const recipients = storedKeys.map(k => k.recipient);
    const file = await buildEncryptedFile(passphrase, recipients, dek);

    const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: 'passphrase.secretum.json' });
    a.click();
    URL.revokeObjectURL(url);

    setEncStatus('Encrypted and downloaded successfully.', 'ok');
  } catch (e) {
    setEncStatus(`Encryption failed: ${e instanceof Error ? e.message : String(e)}`, 'err');
  } finally {
    btnEncrypt.disabled = storedKeys.length === 0;
    btnAddKey.disabled  = false;
  }
});

// ── Decrypt panel ──────────────────────────────────────────────────────────────

function loadEncryptedFileText(text: string): void {
  if (!text.trim()) {
    importedFile = null;
    fileInfoEl.style.display = 'none';
    btnDecrypt.disabled = true;
    return;
  }
  try {
    const file = validateEncryptedFile(JSON.parse(text));
    const nKeys = file.recipients.length;

    fileInfoEl.innerHTML = '';
    const p = document.createElement('p');
    p.className = 'text-[0.8125rem] text-secondary';
    p.innerHTML =
      `<strong>${nKeys}</strong> hardware key${nKeys !== 1 ? 's' : ''} can decrypt this file.`;
    fileInfoEl.appendChild(p);
    fileInfoEl.style.display = '';
    importedFile = file;
    btnDecrypt.disabled = false;
    setDecStatus('', '');
  } catch (e) {
    importedFile = null;
    fileInfoEl.style.display = 'none';
    btnDecrypt.disabled = true;
    setDecStatus(`Invalid encrypted file: ${e instanceof Error ? e.message : String(e)}`, 'err');
  }
}

function readFileAsText(file: File): void {
  const reader = new FileReader();
  reader.onload = ev => {
    const text = ev.target?.result as string;
    fileTextarea.value = text;
    loadEncryptedFileText(text);
  };
  reader.readAsText(file);
}

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('border-secondary/60'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('border-secondary/60'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('border-secondary/60');
  const file = e.dataTransfer?.files[0];
  if (file) readFileAsText(file);
});
fileInput.addEventListener('change', () => { const f = fileInput.files?.[0]; if (f) readFileAsText(f); });
fileTextarea.addEventListener('input', () => loadEncryptedFileText(fileTextarea.value));

btnDecrypt.addEventListener('click', async () => {
  if (!importedFile) { setDecStatus('Import an encrypted file first.', 'err'); return; }
  btnDecrypt.disabled = true;
  hideDecryptResult();

  try {
    if (!importedFile) throw new Error('No encrypted file loaded.');

    setDecStatus('Touch your hardware key…', '');
    const { plaintext } = await decryptEncryptedFile(importedFile);

    showDecryptResult(plaintext);
    setDecStatus('', '');
  } catch (e) {
    setDecStatus(`Decryption failed: ${e instanceof Error ? e.message : String(e)}`, 'err');
  } finally {
    btnDecrypt.disabled = !importedFile;
  }
});

function showDecryptResult(passphrase: string): void {
  decryptValueEl.textContent = passphrase;
  decryptResultEl.style.display = '';
  let remaining = 60;
  decryptSecsEl.textContent  = remaining.toString();
  decryptLabelEl.textContent = `Clears in ${remaining}s`;
  if (decryptClearTimer) clearInterval(decryptClearTimer);
  decryptClearTimer = setInterval(() => {
    remaining -= 1;
    decryptSecsEl.textContent  = remaining.toString();
    decryptLabelEl.textContent = `Clears in ${remaining}s`;
    if (remaining <= 0) hideDecryptResult();
  }, 1000);
}

function hideDecryptResult(): void {
  decryptResultEl.style.display = 'none';
  decryptValueEl.textContent    = '';
  decryptLabelEl.textContent    = '';
  if (decryptClearTimer) { clearInterval(decryptClearTimer); decryptClearTimer = null; }
}

btnDecryptCopy.addEventListener('click', async () => {
  await navigator.clipboard.writeText(decryptValueEl.textContent ?? '');
  btnDecryptCopy.textContent = 'Copied!';
  setTimeout(() => { btnDecryptCopy.textContent = 'Copy'; }, 2000);
});

// ── Init ───────────────────────────────────────────────────────────────────────

renderKeyList();

if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
  (document.getElementById('httpsWarning') as HTMLElement).style.display = '';
}
