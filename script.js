(() => {
  const messageEl = document.getElementById('message');
  const keyEl = document.getElementById('key');
  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');
  const copyBtn = document.getElementById('copyBtn');
  const clearBtn = document.getElementById('clearBtn');
  const qrToggleBtn = document.getElementById('qrToggleBtn');
  const qrContainer = document.getElementById('qrContainer');
  const qrCodeEl = document.getElementById('qrCode');
  const downloadQRBtn = document.getElementById('downloadQRBtn');
  const resultCard = document.getElementById('resultCard');
  const resultEl = document.getElementById('result');
  const warningEl = document.getElementById('warning');
  const togglePassVisibilityBtn = document.getElementById('togglePassVisibility');
  const qrFileInput = document.getElementById('qrFileInput');
  const uploadQRBtn = document.getElementById('uploadQRBtn');

  const PBKDF2_ITERATIONS = 100000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const KEY_LENGTH = 256;

  let qrGenerated = false;
  let qrInstance = null;
  let copyTimeout;

  function showWarning(text) {
    warningEl.textContent = text;
    warningEl.classList.add('show', 'shake');
    setTimeout(() => warningEl.classList.remove('shake'), 450);
  }

  function clearWarning() {
    warningEl.textContent = '';
    warningEl.classList.remove('show');
  }

  function showResult(text) {
    resultEl.textContent = text;
    resultCard.setAttribute('aria-hidden', 'false');
    resultEl.setAttribute('aria-live', 'polite');
    qrContainer.classList.remove('show');
    qrContainer.setAttribute('aria-hidden', 'true');
    qrGenerated = false;
    qrCodeEl.innerHTML = '';
  }

  function clearResult() {
    resultEl.textContent = '';
    resultCard.setAttribute('aria-hidden', 'true');
    resultEl.removeAttribute('aria-live');
    qrContainer.classList.remove('show');
    qrContainer.setAttribute('aria-hidden', 'true');
    qrGenerated = false;
    qrCodeEl.innerHTML = '';
  }

  function concatArrayBuffers(...buffers) {
    const total = buffers.reduce((sum, b) => sum + b.byteLength, 0);
    const tmp = new Uint8Array(total);
    let offset = 0;
    for (const b of buffers) {
      tmp.set(new Uint8Array(b), offset);
      offset += b.byteLength;
    }
    return tmp.buffer;
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function getRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length)).buffer;
  }

  async function deriveKeyFromPassphrase(passphrase, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptString(plaintext, passphrase) {
    const salt = getRandomBytes(SALT_BYTES);
    const iv = getRandomBytes(IV_BYTES);
    const key = await deriveKeyFromPassphrase(passphrase, salt);
    const encoded = new TextEncoder().encode(plaintext);
    const cipherBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      encoded
    );
    return arrayBufferToBase64(concatArrayBuffers(salt, iv, cipherBuffer));
  }

  async function decryptString(payloadBase64, passphrase) {
    const full = base64ToArrayBuffer(payloadBase64);
    if (full.byteLength < (SALT_BYTES + IV_BYTES + 1)) {
      throw new Error('Payload too short or invalid.');
    }
    const fullBytes = new Uint8Array(full);
    const salt = fullBytes.slice(0, SALT_BYTES).buffer;
    const iv = fullBytes.slice(SALT_BYTES, SALT_BYTES + IV_BYTES).buffer;
    const ciphertext = fullBytes.slice(SALT_BYTES + IV_BYTES).buffer;
    const key = await deriveKeyFromPassphrase(passphrase, salt);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      ciphertext
    );
    return new TextDecoder().decode(plainBuffer);
  }

  async function handleEncrypt() {
    clearWarning();
    if (!window.crypto || !crypto.subtle) {
      showWarning('Web Crypto API not supported in this browser.');
      return;
    }
    const plaintext = messageEl.value;
    const pass = keyEl.value;
    if (!plaintext || !plaintext.trim()) {
      clearResult();
      showWarning('Please enter a message to encrypt.');
      return;
    }
    if (!pass || pass.length < 6) {
      showWarning('Passphrase must be at least 6 characters.');
      return;
    }
    try {
      encryptBtn.disabled = true;
      encryptBtn.textContent = 'Encrypting…';
      showResult(await encryptString(plaintext, pass));
    } catch (err) {
      console.error(err);
      showWarning('Encryption failed.');
    } finally {
      encryptBtn.disabled = false;
      encryptBtn.textContent = 'Encrypt';
    }
  }

  async function handleDecrypt() {
    clearWarning();
    if (!window.crypto || !crypto.subtle) {
      showWarning('Web Crypto API not supported in this browser.');
      return;
    }
    const payload = messageEl.value.trim();
    const pass = keyEl.value;
    if (!payload) {
      clearResult();
      showWarning('Please paste the Base64 payload.');
      return;
    }
    if (!pass || pass.length < 6) {
      showWarning('Passphrase must be at least 6 characters.');
      return;
    }
    try {
      decryptBtn.disabled = true;
      decryptBtn.textContent = 'Decrypting…';
      showResult(await decryptString(payload, pass));
    } catch (err) {
      console.error(err);
      showWarning('Failed to decrypt - passphrase may be wrong.');
    } finally {
      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Decrypt';
    }
  }

  async function copyResult() {
    const text = resultEl.textContent;
    if (!text) {
      showWarning('Nothing to copy.');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      resetCopyButtonText();
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      resetCopyButtonText();
    }
  }

  function resetCopyButtonText() {
    clearTimeout(copyTimeout);
    const original = copyBtn.textContent;
    copyBtn.textContent = 'Copied';
    copyTimeout = setTimeout(() => { copyBtn.textContent = original; }, 1300);
  }

  function clearAll() {
    messageEl.value = '';
    keyEl.value = '';
    clearWarning();
    clearResult();
  }

  function toggleQR() {
    if (qrContainer.classList.contains('show')) {
      qrContainer.classList.remove('show');
      qrContainer.setAttribute('aria-hidden', 'true');
      return;
    }
    if (!qrGenerated) {
      try {
        qrInstance = new QRCode(qrCodeEl, {
          text: resultEl.textContent,
          width: 240,
          height: 240,
          colorDark: "#0b1320",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.M
        });
        qrGenerated = true;
      } catch (err) {
        console.error(err);
        showWarning('QR generation failed.');
        return;
      }
    }
    qrContainer.classList.add('show');
    qrContainer.setAttribute('aria-hidden', 'false');
  }

  function downloadQR() {
    if (!qrGenerated) return;
    const canvas = qrCodeEl.querySelector('canvas');
    const img = qrCodeEl.querySelector('img');
    let dataUrl = canvas ? canvas.toDataURL('image/png') : (img && img.src ? img.src : null);
    if (!dataUrl) {
      showWarning('No QR image to download.');
      return;
    }
    const link = document.createElement('a');
    link.href = dataUrl;
    link.download = 'encrypted_qr.png';
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  async function handleQRFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const img = document.createElement('img');
      img.src = URL.createObjectURL(file);
      img.onload = async () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0, img.width, img.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, canvas.width, canvas.height);
        if (!code) {
          showWarning('No QR code found.');
          return;
        }
        messageEl.value = code.data;
        showWarning('QR code loaded - enter passphrase to decrypt.');
      };
    } catch (err) {
      console.error(err);
      showWarning('Failed to process QR image.');
    }
  }

  encryptBtn.addEventListener('click', handleEncrypt);
  decryptBtn.addEventListener('click', handleDecrypt);
  copyBtn.addEventListener('click', copyResult);
  clearBtn.addEventListener('click', clearAll);
  qrToggleBtn.addEventListener('click', toggleQR);
  downloadQRBtn.addEventListener('click', downloadQR);

  if (uploadQRBtn && qrFileInput) {
    uploadQRBtn.addEventListener('click', () => { qrFileInput.click(); });
    qrFileInput.addEventListener('change', handleQRFileUpload);
  }


const scanQRBtn = document.getElementById('scanQRBtn');
const cameraModal = document.getElementById('cameraModal');
const qrVideo = document.getElementById('qrVideo');
const closeScanBtn = document.getElementById('closeScanBtn');
const torchBtn = document.getElementById('torchBtn');

let cameraStream = null;
let scanning = false;
let torchOn = false;
let videoTrack = null;
let scanOnlyMode = false;

async function startCameraQRScan(scanOnly = false) {
  clearWarning();
  scanOnlyMode = scanOnly;

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showWarning('Camera not supported in this browser.');
    return;
  }

  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });

    qrVideo.srcObject = cameraStream;
    cameraModal.setAttribute('aria-hidden', 'false');
    scanning = true;
    scanCameraFrame();
  } catch (err) {
    console.error(err);
    showWarning('Camera access denied.');
  }
}

function stopCameraQRScan() {
  scanning = false;

  if (cameraStream) {
    cameraStream.getTracks().forEach(track => track.stop());
    cameraStream = null;
  }

  cameraModal.setAttribute('aria-hidden', 'true');
  torchOn = false;
  videoTrack = null;
}

async function toggleTorch() {
  if (!cameraStream) {
    showWarning('Start camera first.');
    return;
  }

  const [track] = cameraStream.getVideoTracks();
  videoTrack = track;

  const imageCapture = new ImageCapture(track);
  const capabilities = await imageCapture.getPhotoCapabilities().catch(() => null);

  if (!capabilities || !capabilities.torch) {
    showWarning('Torch not supported on this device.');
    return;
  }

  torchOn = !torchOn;
  try {
    await track.applyConstraints({ advanced: [{ torch: torchOn }] });
    showWarning(`Torch ${torchOn ? 'enabled' : 'disabled'}.`);
  } catch (err) {
    console.error(err);
    showWarning('Failed to toggle torch.');
  }
}

function scanCameraFrame() {
  if (!scanning) return;

  if (qrVideo.videoWidth === 0) {
    requestAnimationFrame(scanCameraFrame);
    return;
  }

  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  canvas.width = qrVideo.videoWidth;
  canvas.height = qrVideo.videoHeight;
  ctx.drawImage(qrVideo, 0, 0, canvas.width, canvas.height);

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(imageData.data, canvas.width, canvas.height);

  if (code && code.data) {
    messageEl.value = code.data;
    showWarning('QR scanned — enter passphrase to decrypt.');
    if (scanOnlyMode) stopCameraQRScan();
    return;
  }

  requestAnimationFrame(scanCameraFrame);
}

if (scanQRBtn) scanQRBtn.addEventListener('click', () => startCameraQRScan(true));
if (closeScanBtn) closeScanBtn.addEventListener('click', stopCameraQRScan);
if (torchBtn) torchBtn.addEventListener('click', toggleTorch);

  clearResult();
})();
