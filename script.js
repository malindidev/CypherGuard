(() => {
  // DOM
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

  const strengthMeterEl = document.getElementById('strengthMeter'); // Passphrase strength meter

  // Crypto settings
  const PBKDF2_ITERATIONS = 100000;
  const SALT_BYTES = 16;   // 128-bit salt
  const IV_BYTES = 12;     // 96-bit IV recommended for AES-GCM
  const KEY_LENGTH = 256;  // AES-256

  // QR state
  let qrGenerated = false;
  let qrInstance = null;

  /* ---------------- UI helpers ---------------- */
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

    // Reset QR state for the new result
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

  /* ---------------- low-level helpers ---------------- */
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

  /* ---------------- crypto functions ---------------- */
  async function deriveKeyFromPassphrase(passphrase, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
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

    return derivedKey;
  }

  // Encrypt plaintext -> Base64(salt || iv || ciphertext)
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

    const joined = concatArrayBuffers(salt, iv, cipherBuffer);
    return arrayBufferToBase64(joined);
  }

  // Decrypt Base64 payload that contains salt || iv || ciphertext
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

  /* ---------------- Passphrase strength meter ---------------- */
  function updateStrengthMeter() {
    const pass = keyEl.value;
    const meter = strengthMeterEl;
    const minLength = 6;
    let score = 0;

    if (pass.length >= minLength) score++;
    if (/[a-z]/.test(pass)) score++;
    if (/[A-Z]/.test(pass)) score++;
    if (/\d/.test(pass)) score++;
    if (/[^A-Za-z0-9]/.test(pass)) score++;

    const strengthTexts = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'];
    const strengthColors = ['#d9534f', '#f0ad4e', '#f7e967', '#5bc0de', '#5cb85c'];

    if (!pass) {
      meter.textContent = '';
      meter.style.color = '';
      return;
    }

    meter.textContent = `Passphrase strength: ${strengthTexts[score - 1] || 'Very Weak'}`;
    meter.style.color = strengthColors[score - 1] || '#d9534f';
  }

  /* ---------------- UI actions ---------------- */
  async function handleEncrypt() {
    clearWarning();

    if (!window.crypto || !crypto.subtle) {
      showWarning('Web Crypto API not supported in this browser. Use a modern browser/HTTPS.');
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
      showWarning('Please enter a passphrase (minimum 6 characters).');
      return;
    }

    try {
      encryptBtn.disabled = true;
      encryptBtn.textContent = 'Encrypting…';
      const b64 = await encryptString(plaintext, pass);
      showResult(b64);
    } catch (err) {
      console.error(err);
      showWarning('Encryption failed — check console for details.');
    } finally {
      encryptBtn.disabled = false;
      encryptBtn.textContent = 'Encrypt';
    }
  }

  async function handleDecrypt() {
    clearWarning();

    if (!window.crypto || !crypto.subtle) {
      showWarning('Web Crypto API not supported in this browser. Use a modern browser/HTTPS.');
      return;
    }

    const payload = messageEl.value.trim();
    const pass = keyEl.value;

    if (!payload) {
      clearResult();
      showWarning('Please paste the Base64 payload to decrypt in the message field.');
      return;
    }
    if (!pass || pass.length < 6) {
      showWarning('Please enter the passphrase used when encrypting (minimum 6 characters).');
      return;
    }

    try {
      decryptBtn.disabled = true;
      decryptBtn.textContent = 'Decrypting…';
      const plain = await decryptString(payload, pass);
      showResult(plain);
    } catch (err) {
      console.error(err);
      if (err instanceof DOMException || /authentication/i.test(err.message) || /tag mismatch/i.test(err.message)) {
        showWarning('Failed to decrypt — the passphrase may be incorrect or the payload is invalid.');
      } else {
        showWarning('Decryption failed — payload may be corrupted or invalid.');
      }
    } finally {
      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Decrypt';
    }
  }

  /* ---------------- Copy result to clipboard ---------------- */
  let copyTimeout;

  async function copyResult() {
    const text = resultEl.textContent;
    if (!text) {
      showWarning('Nothing to copy.');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      resetCopyButtonText();
    } catch (e) {
      // fallback
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        resetCopyButtonText();
      } catch (err) {
        showWarning('Unable to copy—your browser may block clipboard access.');
      }
    }
  }

  function resetCopyButtonText() {
    clearTimeout(copyTimeout);
    const original = copyBtn.textContent;
    copyBtn.textContent = 'Copied';
    copyTimeout = setTimeout(() => {
      copyBtn.textContent = original;
    }, 1300);
  }

  /* ---------------- Clear inputs and output ---------------- */
  function clearAll() {
    messageEl.value = '';
    keyEl.value = '';
    clearWarning();
    clearResult();
    updateStrengthMeter(); // Reset strength meter on clear
  }

  /* ---------------- QR CODE SECTION ---------------- */
  function toggleQR() {
    if (qrContainer.classList.contains('show')) {
      qrContainer.classList.remove('show');
      qrContainer.setAttribute('aria-hidden', 'true');
      return;
    }

    // If we haven't generated the QR for the current result, do so
    if (!qrGenerated) {
      qrCodeEl.innerHTML = '';
      try {
        // QRCode library (qrcode.min.js) - CorrectLevel available on global
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
        console.error('QR generation failed:', err);
        showWarning('Unable to generate QR code.');
        return;
      }
    }
    qrContainer.classList.add('show');
    qrContainer.setAttribute('aria-hidden', 'false');
  }

  function downloadQR() {
    if (!qrGenerated) return;
    // QRCode.js outputs either canvas or img depending on browser; prefer canvas
    const canvas = qrCodeEl.querySelector('canvas');
    const img = qrCodeEl.querySelector('img');
    let dataUrl = null;
    if (canvas) {
      dataUrl = canvas.toDataURL('image/png');
    } else if (img && img.src) {
      dataUrl = img.src;
    }
    if (!dataUrl) {
      showWarning('No QR image available to download.');
      return;
    }
    const link = document.createElement('a');
    link.href = dataUrl;
    link.download = 'encrypted_qr.png';
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  /* ---------------- Event listeners ---------------- */
  encryptBtn.addEventListener('click', handleEncrypt);
  decryptBtn.addEventListener('click', handleDecrypt);
  copyBtn.addEventListener('click', copyResult);
  clearBtn.addEventListener('click', clearAll);
  qrToggleBtn.addEventListener('click', toggleQR);
  downloadQRBtn.addEventListener('click', downloadQR);

  // Focus result when visible (after animation)
  const observer = new MutationObserver(() => {
    const visible = resultCard.getAttribute('aria-hidden') === 'false';
    if (visible && resultEl.textContent) {
      setTimeout(() => resultEl.focus(), 220);
    }
  });
  observer.observe(resultCard, { attributes: true });

  // Pressing Enter in passphrase triggers encrypt
  keyEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleEncrypt();
    }
  });

  // Clear warnings when user types
  [messageEl, keyEl].forEach(el => el.addEventListener('input', clearWarning));

  // Update strength meter live
  keyEl.addEventListener('input', updateStrengthMeter);

  // Initialise UI
  clearResult();
  updateStrengthMeter();
})();
