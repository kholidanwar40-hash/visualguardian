const form = document.querySelector('#securityForm');
const modeSelect = document.querySelector('#mode');
const inputData = document.querySelector('#inputData');
const shiftInput = document.querySelector('#shift');
const secretKeyInput = document.querySelector('#secretKey');
const resultOutput = document.querySelector('#resultOutput');
const processSteps = document.querySelector('#processSteps');
const decryptButton = document.querySelector('#decryptButton');
const copyButton = document.querySelector('#copyButton');

let lastResult = {
  mode: 'caesar',
  input: '',
  output: '',
};

function normalizeShift(value) {
  const shift = Number.parseInt(value, 10);
  if (Number.isNaN(shift)) {
    return 0;
  }

  return ((shift % 26) + 26) % 26;
}

function shiftCharacter(character, shift, direction = 1) {
  const code = character.charCodeAt(0);
  const isUppercase = code >= 65 && code <= 90;
  const isLowercase = code >= 97 && code <= 122;

  if (!isUppercase && !isLowercase) {
    return character;
  }

  const base = isUppercase ? 65 : 97;
  const movedIndex = (code - base + direction * shift + 26) % 26;
  return String.fromCharCode(base + movedIndex);
}

function caesarCipher(text, shift, direction = 1) {
  return [...text].map((character) => shiftCharacter(character, shift, direction)).join('');
}

function textToHexPairs(text) {
  return [...text]
    .map((character) => character.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(' ');
}

function hexPairsToText(hexText) {
  const cleanHex = hexText.replace(/\s+/g, '').trim();

  if (!cleanHex || cleanHex.length % 2 !== 0 || /[^a-fA-F0-9]/.test(cleanHex)) {
    throw new Error('Format hex tidak valid untuk didekripsi.');
  }

  const pairs = cleanHex.match(/.{1,2}/g) || [];
  return pairs.map((pair) => String.fromCharCode(Number.parseInt(pair, 16))).join('');
}

function xorTransform(text, key) {
  if (!key) {
    throw new Error('Kunci XOR tidak boleh kosong.');
  }

  return [...text]
    .map((character, index) => {
      const keyCharacter = key[index % key.length];
      return String.fromCharCode(character.charCodeAt(0) ^ keyCharacter.charCodeAt(0));
    })
    .join('');
}

function maskEmail(value) {
  const [name, domain] = value.split('@');
  if (!name || !domain) {
    return value;
  }

  const visibleName = name.slice(0, Math.min(2, name.length));
  return `${visibleName}${'*'.repeat(Math.max(3, name.length - visibleName.length))}@${domain}`;
}

function maskLongToken(value) {
  if (value.length <= 6) {
    return '*'.repeat(value.length);
  }

  return `${value.slice(0, 3)}${'*'.repeat(value.length - 5)}${value.slice(-2)}`;
}

function maskData(text) {
  return text
    .replace(/[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}/g, maskEmail)
    .replace(/\b\d{7,}\b/g, maskLongToken)
    .replace(/\b[A-Za-z0-9_-]{10,}\b/g, maskLongToken);
}

function base64Encode(text) {
  const bytes = new TextEncoder().encode(text);
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binary);
}

function base64Decode(encodedText) {
  try {
    const binary = atob(encodedText.replace(/\s+/g, ''));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    throw new Error('Format Base64 tidak valid untuk didekode.');
  }
}

async function sha256Hash(text) {
  if (!window.crypto?.subtle) {
    throw new Error('Browser ini tidak mendukung SHA-256 Web Crypto.');
  }

  const bytes = new TextEncoder().encode(text);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function setSteps(steps) {
  processSteps.innerHTML = '';

  steps.forEach((step) => {
    const item = document.createElement('li');
    item.textContent = step;
    processSteps.appendChild(item);
  });
}

function setResult(output, steps, mode, input) {
  resultOutput.textContent = output || 'Tidak ada output.';
  setSteps(steps);
  lastResult = { mode, input, output };
}

async function processData(event) {
  event.preventDefault();

  const mode = modeSelect.value;
  const text = inputData.value;
  const shift = normalizeShift(shiftInput.value);
  const key = secretKeyInput.value;

  try {
    if (mode === 'caesar') {
      const encrypted = caesarCipher(text, shift);
      setResult(encrypted, [
        `Ambil setiap karakter pada input: "${text}".`,
        `Jika karakter adalah huruf, geser posisinya sebanyak ${shift}.`,
        'Karakter selain huruf seperti angka, spasi, dan simbol tetap dipertahankan.',
        'Gabungkan seluruh karakter hasil geser menjadi output terenkripsi.',
      ], mode, text);
      return;
    }

    if (mode === 'xor') {
      const encryptedText = xorTransform(text, key);
      const encryptedHex = textToHexPairs(encryptedText);
      setResult(encryptedHex, [
        `Gunakan kunci "${key}" dan ulangi kunci sampai panjangnya sama dengan data.`,
        'Ubah tiap karakter input dan karakter kunci menjadi kode angka ASCII/Unicode.',
        'Lakukan operasi XOR pada pasangan kode angka tersebut.',
        'Ubah hasil XOR ke format hex agar aman ditampilkan sebagai teks.',
      ], mode, text);
      return;
    }

    if (mode === 'mask') {
      const masked = maskData(text);
      setResult(masked, [
        'Deteksi pola data sensitif seperti email, nomor panjang, atau token panjang.',
        'Pertahankan sebagian karakter awal/akhir agar data masih bisa dikenali.',
        'Ganti bagian tengah data dengan tanda bintang sebagai penyamaran.',
        'Output masking tidak perlu didekripsi karena tujuannya hanya menyembunyikan sebagian data.',
      ], mode, text);
      return;
    }

    if (mode === 'hash') {
      const hashed = await sha256Hash(text);
      setResult(hashed, [
        'Ubah input menjadi byte menggunakan TextEncoder.',
        'Proses byte dengan algoritma SHA-256 dari Web Crypto API.',
        'Hasil digest diubah ke format hex sepanjang 64 karakter.',
        'Hash bersifat satu arah, jadi tidak bisa didekripsi kembali menjadi data asli.',
      ], mode, text);
      return;
    }

    const encoded = base64Encode(text);
    setResult(encoded, [
      'Ubah input menjadi byte agar karakter Indonesia dan simbol tetap aman.',
      'Konversi byte ke format Base64 menggunakan karakter A-Z, a-z, 0-9, +, /, dan =.',
      'Base64 bukan enkripsi kuat, tetapi berguna untuk encoding data agar aman dikirim sebagai teks.',
      'Output Base64 dapat didekode kembali ke data asli.',
    ], mode, text);
  } catch (error) {
    setResult(error.message, ['Validasi gagal. Periksa input dan parameter algoritma.'], mode, text);
  }
}

function decryptCurrentOutput() {
  const mode = lastResult.mode;
  const output = lastResult.output;
  const shift = normalizeShift(shiftInput.value);
  const key = secretKeyInput.value;

  try {
    if (mode === 'caesar') {
      const decrypted = caesarCipher(output, shift, -1);
      setResult(decrypted, [
        `Ambil output Caesar Cipher: "${output}".`,
        `Geser setiap huruf kembali sebanyak ${shift} posisi ke arah sebaliknya.`,
        'Karakter non-huruf tetap sama.',
        'Hasil akhirnya kembali menjadi data asli jika shift yang digunakan benar.',
      ], mode, lastResult.input);
      return;
    }

    if (mode === 'xor') {
      const encryptedText = hexPairsToText(output);
      const decrypted = xorTransform(encryptedText, key);
      setResult(decrypted, [
        'Ubah output hex kembali menjadi karakter hasil XOR.',
        `Gunakan kunci yang sama: "${key}".`,
        'Lakukan XOR ulang karena operasi XOR bersifat reversible.',
        'Jika kunci benar, output kembali ke data asli.',
      ], mode, lastResult.input);
      return;
    }

    if (mode === 'base64') {
      const decoded = base64Decode(output);
      setResult(decoded, [
        `Ambil output Base64: "${output}".`,
        'Decode karakter Base64 kembali menjadi byte asli.',
        'Ubah byte menjadi teks memakai TextDecoder.',
        'Hasil akhirnya kembali menjadi data asli jika format Base64 valid.',
      ], mode, lastResult.input);
      return;
    }

    setSteps([
      mode === 'hash' ? 'SHA-256 adalah hash satu arah, bukan enkripsi dua arah.' : 'Data masking tidak memiliki proses dekripsi.',
      mode === 'hash' ? 'Hash hanya cocok untuk verifikasi, misalnya membandingkan password atau integritas data.' : 'Bagian yang sudah diganti bintang dianggap tidak tersedia lagi di output publik.',
      'Untuk sistem nyata, data asli harus tetap disimpan di server yang aman jika masih diperlukan.',
    ]);
  } catch (error) {
    setResult(error.message, ['Dekripsi gagal. Pastikan output dan kunci masih sesuai.'], mode, lastResult.input);
  }
}

async function copyOutput() {
  const text = resultOutput.textContent;

  if (!text || text === 'Output akan muncul di sini.') {
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    copyButton.textContent = 'Tersalin';
    window.setTimeout(() => {
      copyButton.textContent = 'Salin';
    }, 1400);
  } catch {
    copyButton.textContent = 'Gagal';
    window.setTimeout(() => {
      copyButton.textContent = 'Salin';
    }, 1400);
  }
}

modeSelect.addEventListener('change', () => {
  const mode = modeSelect.value;
  const cannotDecrypt = mode === 'mask' || mode === 'hash';
  decryptButton.disabled = cannotDecrypt;
  decryptButton.style.opacity = cannotDecrypt ? '0.5' : '1';
});

form.addEventListener('submit', processData);
decryptButton.addEventListener('click', decryptCurrentOutput);
copyButton.addEventListener('click', copyOutput);

form.dispatchEvent(new Event('submit'));
