const form = document.getElementById('cryptoForm');
const messageEl = document.getElementById('message');
const keyEl = document.getElementById('key');
const togglePassBtn = document.getElementById('togglePassBtn');
const strengthWrap = document.getElementById('strength');
const strengthFill = document.getElementById('strengthFill');
const strengthLabel = document.getElementById('strengthLabel');

const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const warningEl = document.getElementById('warning');

const resultCard = document.getElementById('resultCard');
const resultLabel = document.getElementById('resultLabel');
const resultEl = document.getElementById('result');
const copyBtn = document.getElementById('copyBtn');
const clearBtn = document.getElementById('clearBtn');
const qrToggleBtn = document.getElementById('qrToggleBtn');
const scanQRBtn = document.getElementById('scanQRBtn');
const uploadQRBtn = document.getElementById('uploadQRBtn');
const qrFileInput = document.getElementById('qrFileInput');

const qrContainer = document.getElementById('qrContainer');
const qrCodeEl = document.getElementById('qrCode');
const downloadQRBtn = document.getElementById('downloadQRBtn');

const cameraModal = document.getElementById('cameraModal');
const qrVideo = document.getElementById('qrVideo');
const torchBtn = document.getElementById('torchBtn');
const closeScanBtn = document.getElementById('closeScanBtn');

const toastContainer = document.getElementById('toastContainer');

let qrInstance = null;
let cameraStream = null;
let scanRafId = null;
let torchOn = false;

function showToast(msg, type = 'error') {
  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'success') toast.classList.add('success');
  toast.textContent = msg;
  toastContainer.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

let warnTimeout;
function showWarning(msg) {
  clearTimeout(warnTimeout);
  warningEl.textContent = msg;
  warningEl.classList.add('show', 'shake');
  setTimeout(() => warningEl.classList.remove('shake'), 450);
  warnTimeout = setTimeout(() => warningEl.classList.remove('show'), 4000);
}

togglePassBtn.addEventListener('click', () => {
  const isPassword = keyEl.type === 'password';
  keyEl.type = isPassword ? 'text' : 'password';
  togglePassBtn.classList.toggle('active', isPassword);
});

keyEl.addEventListener('input', () => {
  const val = keyEl.value;
  if (!val) {
    strengthWrap.classList.remove('show');
    return;
  }
  strengthWrap.classList.add('show');

  let score = 0;
  if (val.length >= 6) score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;

  const levels = [
    { pct: 20, color: '#ff5d7a', label: 'Very weak' },
    { pct: 40, color: '#ff8a5d', label: 'Weak' },
    { pct: 60, color: '#ffd15d', label: 'Fair' },
    { pct: 80, color: '#8de85d', label: 'Strong' },
    { pct: 100, color: '#37e8c9', label: 'Very strong' },
  ];
  const lvl = levels[Math.min(score, levels.length) - 1] || levels[0];
  strengthFill.style.width = `${lvl.pct}%`;
  strengthFill.style.background = lvl.color;
  strengthLabel.textContent = lvl.label;
});

const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64(bytes) {
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
function fromBase64(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptMessage(message, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(message)));
  const payload = new Uint8Array(salt.length + iv.length + ciphertext.length);
  payload.set(salt, 0);
  payload.set(iv, salt.length);
  payload.set(ciphertext, salt.length + iv.length);
  return toBase64(payload);
}

async function decryptMessage(payloadB64, passphrase) {
  const payload = fromBase64(payloadB64.trim());
  if (payload.length < 29) throw new Error('malformed');
  const salt = payload.slice(0, 16);
  const iv = payload.slice(16, 28);
  const ciphertext = payload.slice(28);
  const key = await deriveKey(passphrase, salt);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return dec.decode(plainBuf);
}

function showResult(text, label) {
  resultLabel.textContent = label;
  resultEl.textContent = text;
  resultCard.setAttribute('aria-hidden', 'false');
  qrContainer.classList.remove('show');
  qrContainer.setAttribute('aria-hidden', 'true');
}

encryptBtn.addEventListener('click', async () => {
  const message = messageEl.value;
  const passphrase = keyEl.value;
  if (!message.trim()) return showWarning('Enter a message to encrypt.');
  if (passphrase.length < 6) return showWarning('Passphrase must be at least 6 characters.');

  encryptBtn.disabled = true;
  try {
    const result = await encryptMessage(message, passphrase);
    showResult(result, 'Encrypted (base64)');
    showToast('Message encrypted!', 'success');
  } catch (err) {
    console.error(err);
    showWarning('Encryption failed. Please try again.');
  }
  encryptBtn.disabled = false;
});

decryptBtn.addEventListener('click', async () => {
  const message = messageEl.value;
  const passphrase = keyEl.value;
  if (!message.trim()) return showWarning('Paste the encrypted text to decrypt.');
  if (!passphrase) return showWarning('Enter the passphrase used to encrypt it.');

  decryptBtn.disabled = true;
  try {
    const result = await decryptMessage(message, passphrase);
    showResult(result, 'Decrypted');
    showToast('Message decrypted!', 'success');
  } catch (err) {
    showWarning('Decryption failed. Check your passphrase and ciphertext.');
  }
  decryptBtn.disabled = false;
});

copyBtn.addEventListener('click', () => {
  const text = resultEl.textContent.trim();
  if (!text) return showToast('Nothing to copy.');
  navigator.clipboard.writeText(text)
    .then(() => showToast('Copied to clipboard!', 'success'))
    .catch(() => showToast('Failed to copy.'));
});

clearBtn.addEventListener('click', () => {
  resultEl.textContent = '';
  resultCard.setAttribute('aria-hidden', 'true');
  qrContainer.classList.remove('show');
  qrContainer.setAttribute('aria-hidden', 'true');
});

qrToggleBtn.addEventListener('click', () => {
  const text = resultEl.textContent.trim();
  if (!text) return showToast('Nothing to encode yet.');

  const isShown = qrContainer.classList.contains('show');
  if (isShown) {
    qrContainer.classList.remove('show');
    qrContainer.setAttribute('aria-hidden', 'true');
    return;
  }

  qrCodeEl.innerHTML = '';
  qrInstance = new QRCode(qrCodeEl, {
    text,
    width: 220,
    height: 220,
    colorDark: '#06131a',
    colorLight: '#ffffff',
    correctLevel: QRCode.CorrectLevel.M,
  });
  qrContainer.classList.add('show');
  qrContainer.setAttribute('aria-hidden', 'false');
});

downloadQRBtn.addEventListener('click', () => {
  const canvas = qrCodeEl.querySelector('canvas');
  if (!canvas) return showToast('Generate a QR code first.');
  const link = document.createElement('a');
  link.download = 'cypherguard-qr.png';
  link.href = canvas.toDataURL('image/png');
  link.click();
  showToast('QR downloaded!', 'success');
});

uploadQRBtn.addEventListener('click', () => qrFileInput.click());

qrFileInput.addEventListener('change', e => {
  const file = e.target.files[0];
  if (!file) return;
  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);
    if (code) {
      messageEl.value = code.data;
      showToast('QR decoded into message field!', 'success');
    } else {
      showToast('No QR code found in that image.');
    }
    URL.revokeObjectURL(img.src);
  };
  img.src = URL.createObjectURL(file);
  qrFileInput.value = '';
});

scanQRBtn.addEventListener('click', async () => {
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    qrVideo.srcObject = cameraStream;
    cameraModal.setAttribute('aria-hidden', 'false');
    await qrVideo.play();
    scanLoop();
  } catch (err) {
    showToast('Camera access denied.');
  }
});

function scanLoop() {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  const tick = () => {
    if (!cameraStream) return;
    if (qrVideo.readyState === qrVideo.HAVE_ENOUGH_DATA) {
      canvas.width = qrVideo.videoWidth;
      canvas.height = qrVideo.videoHeight;
      ctx.drawImage(qrVideo, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code && code.data) {
        messageEl.value = code.data;
        showToast('QR scanned into message field!', 'success');
        stopScan();
        return;
      }
    }
    scanRafId = requestAnimationFrame(tick);
  };
  scanRafId = requestAnimationFrame(tick);
}

function stopScan() {
  if (scanRafId) cancelAnimationFrame(scanRafId);
  scanRafId = null;
  cameraModal.setAttribute('aria-hidden', 'true');
  if (cameraStream) {
    cameraStream.getTracks().forEach(t => t.stop());
    cameraStream = null;
  }
  torchOn = false;
  torchBtn.classList.remove('active');
}

closeScanBtn.addEventListener('click', stopScan);

torchBtn.addEventListener('click', async () => {
  if (!cameraStream) return;
  const track = cameraStream.getVideoTracks()[0];
  const capabilities = track.getCapabilities ? track.getCapabilities() : {};
  if (!capabilities.torch) return showToast('Torch not supported on this device.');
  try {
    torchOn = !torchOn;
    await track.applyConstraints({ advanced: [{ torch: torchOn }] });
    torchBtn.classList.toggle('active', torchOn);
  } catch {
    showToast('Could not toggle torch.');
  }
});
