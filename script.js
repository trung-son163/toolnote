/* ============================================================
   PERSONAL SECURE HUB — script.js  (Firebase + CryptoJS Edition)
   Dữ liệu được mã hóa AES TRƯỚC KHI gửi lên Firebase.
   Google/Firebase không thể đọc nội dung của bạn.
   ============================================================ */

'use strict';

/* ████████████████████████████████████████████████████████████
   BƯỚC 1 — DÁN CẤU HÌNH FIREBASE CỦA BẠN VÀO ĐÂY
   ████████████████████████████████████████████████████████████

   Hướng dẫn lấy cấu hình Firebase (miễn phí):
   ─────────────────────────────────────────────
   1. Truy cập: https://console.firebase.google.com
   2. Nhấn "Add project" → đặt tên → tắt Google Analytics → Create project
   3. Sau khi tạo xong, nhấn biểu tượng "</>" (Web) trên trang Overview
   4. Đặt tên app → nhấn "Register app"
   5. Sao chép toàn bộ object firebaseConfig và dán vào bên dưới
   6. Quay lại Console → Build → Firestore Database → Create database
      → Chọn "Start in test mode" → Chọn vị trí gần nhất → Enable
   7. Vào Firestore → Rules → Thay toàn bộ nội dung bằng:

      rules_version = '2';
      service cloud.firestore {
        match /databases/{database}/documents {
          match /psh_data/{document=**} {
            allow read, write: if true;
          }
        }
      }

      → Publish. (Bảo mật thực sự đến từ mã hóa AES phía client)

   ────────────────────────────────────────────────────────────
   Nếu để nguyên "YOUR_...", app vẫn hoạt động với LocalStorage.
   ████████████████████████████████████████████████████████████ */

const FIREBASE_CONFIG = {
   apiKey: "AIzaSyD_iUztkprfq5Jr_BwNH9O3nA0VKjNUV2w",
  authDomain: "tool-2aa87.firebaseapp.com",
  projectId: "tool-2aa87",
  storageBucket: "tool-2aa87.firebasestorage.app",
  messagingSenderId: "640804467803",
  appId: "1:640804467803:web:bcda1e60a8de5e12e83b7e"
};

/* Tự động phát hiện chế độ: Firebase hay LocalStorage */
const USE_FIREBASE = (
  typeof firebase !== 'undefined' &&
  typeof CryptoJS !== 'undefined' &&
  !FIREBASE_CONFIG.apiKey.includes('YOUR_')
);

/* ============================================================
   CONSTANTS
   ============================================================ */
const STORAGE = {
  HASH:      'psh_pw_hash_v2',
  AUTH_MODE: 'psh_auth_mode',
  CACHE:     'psh_items_cache',   // Cache offline
};

const FIRESTORE_COL   = 'psh_data';   // Tên collection Firestore
const AUTO_LOCK_MS    = 5 * 60 * 1000;
const MAX_ATTEMPTS    = 5;
const LOCKOUT_MS      = 30 * 1000;
const WARN_THRESHOLD  = 60 * 1000;
const PBKDF2_ITERS    = 5000;
const PBKDF2_KEYSIZE  = 256 / 32;
const IMG_MAX_PX      = 1200;      // Max chiều ảnh sau khi nén
const IMG_QUALITY     = 0.78;      // Chất lượng JPEG sau khi nén

/* ============================================================
   STATE — Trạng thái ứng dụng
   ============================================================ */
const state = {
  isLocked:       true,
  currentSection: 'dashboard',
  currentFilter:  'all',
  searchQuery:    '',
  items:          [],

  /* Xác thực */
  loginAttempts:  0,
  lockedUntil:    0,
  setupMode:      'password',
  setupPinBuffer: '',
  loginPinBuffer: '',

  /* Mã hóa + Firebase — chỉ tồn tại trong RAM, bị xóa khi khóa */
  encKey:   null,
  userId:   null,
  syncUnsub: null,
  syncStatus: 'local',

  /* Auto-lock */
  timerInterval:   null,
  autoLockEndTime: 0,

  /* Calculator */
  calc: {
    display:      '0',
    history:      '',
    accumulator:  null,
    operator:     null,
    waitingInput: false,
    justCalc:     false,
  },

  /* UI */
  fabOpen:         false,
  calcVisible:     false,
  confirmCb:       null,
  pendingItemType: null,
  editingItemId:   null,   // null = thêm mới, có id = đang sửa
  imageBase64:     null,
  imageFileName:   null,
  docBase64:       null,
  docFileName:     null,
  docMimeType:     null,
  docFileSize:     0,
};

/* ============================================================
   FIREBASE INIT
   ============================================================ */
let db = null;

function initFirebase() {
  if (!USE_FIREBASE) {
    updateSyncStatus('local');
    return;
  }
  try {
    if (!firebase.apps.length) {
      firebase.initializeApp(FIREBASE_CONFIG);
    }
    db = firebase.firestore();

    /* Bật persistence offline — Firebase tự cache vào IndexedDB */
    db.enablePersistence({ synchronizeTabs: true })
      .catch(err => {
        if (err.code !== 'failed-precondition' && err.code !== 'unimplemented') {
          console.warn('Firebase offline persistence:', err.code);
        }
      });

    /* Theo dõi kết nối mạng */
    window.addEventListener('online',  () => { if (!state.isLocked) updateSyncStatus('syncing'); });
    window.addEventListener('offline', () => { if (!state.isLocked) updateSyncStatus('offline'); });

    console.log('[PSH] Firebase đã kết nối — Chế độ mã hóa đầu cuối');
  } catch (err) {
    console.error('[PSH] Lỗi Firebase:', err);
    db = null;
  }
}

/* ============================================================
   CRYPTO — Mã hóa AES với CryptoJS (client-side only)
   ============================================================ */

/* Phái sinh userId 20 ký tự từ mật khẩu — dùng làm đường dẫn Firestore */
function deriveUserId(password) {
  return CryptoJS.SHA256(password + '_psh_uid_v2').toString().slice(0, 20);
}

/* Phái sinh khóa AES 256-bit từ mật khẩu bằng PBKDF2 */
function deriveEncKey(password, userId) {
  return CryptoJS.PBKDF2(password, userId + '_enc_salt_v2', {
    keySize:    PBKDF2_KEYSIZE,
    iterations: PBKDF2_ITERS,
    hasher:     CryptoJS.algo.SHA256,
  }).toString();
}

/* Mã hóa item object thành chuỗi AES ciphertext */
function encryptItem(item) {
  if (!state.encKey) return null;
  try {
    return CryptoJS.AES.encrypt(JSON.stringify(item), state.encKey).toString();
  } catch (e) {
    console.error('[PSH] Lỗi mã hóa:', e);
    return null;
  }
}

/* Giải mã chuỗi AES ciphertext về item object */
function decryptItem(encStr) {
  if (!state.encKey || !encStr) return null;
  try {
    const bytes = CryptoJS.AES.decrypt(encStr, state.encKey);
    const json  = bytes.toString(CryptoJS.enc.Utf8);
    return json ? JSON.parse(json) : null;
  } catch {
    return null;
  }
}

/* Băm mật khẩu để xác thực (SubtleCrypto — async, không block UI) */
async function hashPasswordForAuth(raw) {
  const data   = new TextEncoder().encode(raw + '_psh_auth_v2');
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ============================================================
   AUTH — Thiết lập và xác minh mật khẩu
   ============================================================ */
async function setupPassword(raw) {
  const hash = await hashPasswordForAuth(raw);
  localStorage.setItem(STORAGE.HASH, hash);
  localStorage.setItem(STORAGE.AUTH_MODE, state.setupMode);
}

async function verifyPassword(raw) {
  const stored = localStorage.getItem(STORAGE.HASH);
  if (!stored) return false;
  return (await hashPasswordForAuth(raw)) === stored;
}

const isPasswordSet = () => !!localStorage.getItem(STORAGE.HASH);
const getAuthMode   = () => localStorage.getItem(STORAGE.AUTH_MODE) || 'password';

/* ============================================================
   LOCK / UNLOCK
   ============================================================ */
async function attemptLogin(input) {
  if (state.lockedUntil > Date.now()) {
    const secs = Math.ceil((state.lockedUntil - Date.now()) / 1000);
    showLoginError(`Tài khoản tạm khóa. Thử lại sau ${secs}s.`);
    resetLoginPin();
    return;
  }

  setLoginBusy(true);
  await sleep(60);

  /* ── THIẾT BỊ MỚI: chưa có hash cục bộ, dùng Firebase để xác minh ── */
  if (!isPasswordSet() && USE_FIREBASE && db) {
    await attemptNewDeviceLogin(input);
    return;
  }

  /* ── ĐĂNG NHẬP THÔNG THƯỜNG ── */
  const valid = await verifyPassword(input);

  if (valid) {
    if (USE_FIREBASE) {
      state.userId = deriveUserId(input);
      state.encKey = deriveEncKey(input, state.userId);
    }
    state.loginAttempts = 0;
    hide($('loginError'));
    doUnlock();
  } else {
    setLoginBusy(false);
    state.loginAttempts++;
    resetLoginPin();
    shakePinDisplay('loginPinDisplay');

    if (state.loginAttempts >= MAX_ATTEMPTS) {
      state.lockedUntil   = Date.now() + LOCKOUT_MS;
      state.loginAttempts = 0;
      showLoginError(`Sai ${MAX_ATTEMPTS} lần! Khóa ${LOCKOUT_MS / 1000}s.`);
    } else {
      showLoginError(`Sai mật khẩu. Còn ${MAX_ATTEMPTS - state.loginAttempts} lần thử.`);
    }
    if ($('loginPassword')) $('loginPassword').value = '';
  }
}

/* Xác minh mật khẩu trên thiết bị mới bằng cách thử giải mã dữ liệu Firebase */
async function attemptNewDeviceLogin(input) {
  if (input.length < 4) {
    setLoginBusy(false);
    showLoginError('Mật khẩu phải có ít nhất 4 ký tự.');
    return;
  }

  /* Phái sinh keys thử nghiệm */
  const tryUserId = deriveUserId(input);
  const tryEncKey = deriveEncKey(input, tryUserId);

  try {
    const colRef   = db.collection(FIRESTORE_COL).doc(tryUserId).collection('items');
    const snapshot = await colRef.limit(3).get();

    if (!snapshot.empty) {
      /* Có dữ liệu trên cloud — thử giải mã để xác minh mật khẩu đúng */
      let canDecrypt = false;
      snapshot.docs.forEach(doc => {
        const raw = doc.data();
        if (raw.d) {
          try {
            const bytes = CryptoJS.AES.decrypt(raw.d, tryEncKey);
            const json  = bytes.toString(CryptoJS.enc.Utf8);
            if (json && JSON.parse(json)) canDecrypt = true;
          } catch { /* sai key */ }
        }
      });

      if (!canDecrypt) {
        /* Sai mật khẩu — có dữ liệu nhưng không giải mã được */
        setLoginBusy(false);
        state.loginAttempts++;
        resetLoginPin();
        shakePinDisplay('loginPinDisplay');
        showLoginError('Sai mật khẩu! Dữ liệu cloud không khớp.');
        if ($('loginPassword')) $('loginPassword').value = '';
        return;
      }
    }
    /* Đúng mật khẩu (hoặc chưa có dữ liệu → kho mới) → lưu hash & mở khoá */
    state.setupMode = 'password';
    await setupPassword(input);
    state.userId = tryUserId;
    state.encKey = tryEncKey;
    state.loginAttempts = 0;
    hide($('loginError'));
    doUnlock();

  } catch (err) {
    /* Lỗi mạng — cho đăng nhập offline, sẽ sync sau */
    console.warn('[PSH] Firebase verify lỗi, đăng nhập offline:', err);
    state.setupMode = 'password';
    await setupPassword(input);
    state.userId = tryUserId;
    state.encKey = tryEncKey;
    hide($('loginError'));
    doUnlock();
  }
}

function doUnlock() {
  state.isLocked = false;
  loadLocalCache();

  const ls = $('lockScreen');
  ls.classList.add('unlocking');

  setTimeout(() => {
    ls.classList.add('hidden');
    ls.classList.remove('unlocking');
    $('app').classList.remove('hidden');
    startAutoLock();
    renderAll();

    /* Kết nối Firestore sau khi giao diện đã hiện (không block) */
    if (USE_FIREBASE && db) {
      setTimeout(() => subscribeToCloud(), 400);
      showToast('Đã mở khoá — Đang đồng bộ Firebase...', 'success');
    } else {
      showToast('Đã mở khoá (Chế độ LocalStorage)', 'success');
    }
  }, 600);
}

function lockApp() {
  state.isLocked    = true;
  state.fabOpen     = false;
  state.calcVisible = false;

  /* Huỷ listener và xóa key khỏi RAM ngay lập tức */
  unsubscribeFromCloud();
  state.encKey  = null;
  state.userId  = null;

  stopAutoLock();
  updateSyncStatus('local');
  document.body.classList.remove('calc-open');
  $('app').classList.add('hidden');

  const ls = $('lockScreen');
  ls.classList.remove('hidden');
  ls.style.transition = 'none';
  ls.style.opacity    = '0';
  ls.style.transform  = 'scale(0.98)';
  requestAnimationFrame(() => {
    ls.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    ls.style.opacity    = '1';
    ls.style.transform  = 'scale(1)';
  });

  resetLoginPin();
  if ($('loginPassword')) $('loginPassword').value = '';
  hide($('loginError'));
  setLoginBusy(false);
  showToast('Ứng dụng đã được khóa.', 'info');
}

/* ============================================================
   FIREBASE SYNC — Real-time Firestore
   ============================================================ */
function subscribeToCloud() {
  if (!db || !state.userId) return;
  updateSyncStatus('syncing');

  const colRef = db.collection(FIRESTORE_COL).doc(state.userId).collection('items');

  state.syncUnsub = colRef.onSnapshot(
    snapshot => {
      let changed = false;

      snapshot.docChanges().forEach(change => {
        if (change.type === 'added' || change.type === 'modified') {
          const raw  = change.doc.data();
          const item = decryptItem(raw.d);
          if (!item) return; // Bỏ qua nếu không giải mã được

          const idx = state.items.findIndex(i => i.id === item.id);
          if (idx === -1) {
            state.items.push(item);
            changed = true;
          } else if ((item.updatedAt || 0) > (state.items[idx].updatedAt || 0)) {
            /* Remote mới hơn → ghi đè local */
            state.items[idx] = item;
            changed = true;
          }

        } else if (change.type === 'removed') {
          const id  = change.doc.id;
          const idx = state.items.findIndex(i => i.id === id);
          if (idx !== -1) { state.items.splice(idx, 1); changed = true; }
        }
      });

      if (changed) {
        /* Dedup phòng ngừa: loại bỏ item trùng id trước khi render */
        const seen = new Set();
        state.items = state.items.filter(item => {
          if (seen.has(item.id)) return false;
          seen.add(item.id);
          return true;
        });
        saveLocalCache();
        renderAll();
      }
      updateSyncStatus('synced');
    },
    err => {
      console.error('[PSH] Firestore error:', err);
      updateSyncStatus('error');
      showToast('Lỗi kết nối Firebase. Đang dùng cache cục bộ.', 'warning');
    }
  );
}

function unsubscribeFromCloud() {
  if (typeof state.syncUnsub === 'function') {
    state.syncUnsub();
    state.syncUnsub = null;
  }
}

/* Ghi một item lên Firestore (mã hóa AES trước khi gửi) */
async function pushItemToCloud(item) {
  if (!db || !state.userId) return;
  const encrypted = encryptItem(item);
  if (!encrypted) { console.warn('[PSH] Không thể mã hóa item'); return; }

  try {
    await db.collection(FIRESTORE_COL).doc(state.userId)
      .collection('items').doc(item.id).set({
        d: encrypted,                                          // d = data (encrypted)
        t: firebase.firestore.FieldValue.serverTimestamp(),   // t = timestamp
      });
  } catch (err) {
    console.error('[PSH] Lỗi ghi Firestore:', err);
    showToast('Lỗi đồng bộ — sẽ thử lại khi có mạng.', 'warning');
  }
}

/* Xóa một item khỏi Firestore */
async function removeItemFromCloud(itemId) {
  if (!db || !state.userId) return;
  try {
    await db.collection(FIRESTORE_COL).doc(state.userId)
      .collection('items').doc(itemId).delete();
  } catch (err) {
    console.error('[PSH] Lỗi xóa Firestore:', err);
  }
}

/* Cập nhật badge trạng thái đồng bộ trên header */
function updateSyncStatus(status) {
  state.syncStatus = status;
  const el = $('syncStatus');
  if (!el) return;
  el.className = `sync-status ${status}`;
  const labels = {
    local:   'LOCAL',
    syncing: 'SYNC...',
    synced:  'SYNCED',
    error:   'ERROR',
    offline: 'OFFLINE',
  };
  $('syncStatusText').textContent = labels[status] || 'LOCAL';
}

/* ============================================================
   LOCAL CACHE — LocalStorage làm bộ nhớ offline
   ============================================================ */
function loadLocalCache() {
  try {
    const raw = localStorage.getItem(STORAGE.CACHE);
    state.items = raw ? JSON.parse(raw) : [];
  } catch { state.items = []; }
}

function saveLocalCache() {
  try {
    /* Với ảnh Base64 lớn, cache có thể đầy — bỏ qua ảnh nếu cần */
    const data = JSON.stringify(state.items);
    localStorage.setItem(STORAGE.CACHE, data);
  } catch (e) {
    /* Thử lưu không kèm ảnh nếu bị lỗi quota */
    try {
      const lite = state.items.map(i => i.type === 'image' ? { ...i, content: '[cached]' } : i);
      localStorage.setItem(STORAGE.CACHE, JSON.stringify(lite));
      showToast('Cache đầy — ảnh chỉ xem được khi có mạng.', 'warning');
    } catch { /* Bỏ qua */ }
  }
}

/* ============================================================
   DATA OPERATIONS — CRUD tích hợp local + cloud
   ============================================================ */

/* Thêm mới (local-first: hiện ngay, gửi cloud async) */
function persistItem(item) {
  saveLocalCache();
  renderAll();
  if (USE_FIREBASE) pushItemToCloud(item);
}

function moveToTrash(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;
  item.inTrash   = true;
  item.trashedAt = Date.now();
  item.updatedAt = Date.now();
  persistItem(item);
  showToast(`"${item.title}" đã vào thùng rác.`, 'warning');
}

function restoreItem(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;
  item.inTrash   = false;
  item.trashedAt = null;
  item.updatedAt = Date.now();
  persistItem(item);
  showToast(`"${item.title}" đã được khôi phục.`, 'success');
}

function deletePermanent(id) {
  const idx = state.items.findIndex(i => i.id === id);
  if (idx === -1) return;
  const [removed] = state.items.splice(idx, 1);
  saveLocalCache();
  renderAll();
  if (USE_FIREBASE) removeItemFromCloud(id);
  showToast(`"${removed.title}" đã xóa vĩnh viễn.`, 'error');
}

function confirmDeletePermanent(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;
  showConfirm(
    'XÓA VĨNH VIỄN',
    `Xóa <strong>"${escHtml(item.title)}"</strong>?<br>Hành động này không thể hoàn tác.`,
    () => deletePermanent(id)
  );
}

function emptyTrash() {
  const trash = state.items.filter(i => i.inTrash);
  if (!trash.length) { showToast('Thùng rác trống.', 'info'); return; }
  showConfirm(
    'XÓA TẤT CẢ THÙNG RÁC',
    `Xóa vĩnh viễn <strong>${trash.length} mục</strong>?<br>Không thể hoàn tác!`,
    () => {
      const ids = trash.map(i => i.id);
      state.items = state.items.filter(i => !i.inTrash);
      saveLocalCache();
      renderAll();
      if (USE_FIREBASE) ids.forEach(id => removeItemFromCloud(id));
      showToast(`Đã xóa ${ids.length} mục.`, 'success');
    }
  );
}

/* Kiểm tra thiết bị iOS (Safari không hỗ trợ download attribute với data: URL) */
function isIOS() {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

/* Chuyển đổi data: URL → Blob (bắt buộc để download hoạt động trên mobile) */
function dataUrlToBlob(dataUrl) {
  const parts  = dataUrl.split(',');
  const mime   = parts[0].match(/:(.*?);/)[1];
  const binary = atob(parts[1]);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type: mime });
}

async function downloadItem(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;

  if (item.content === '[cached]') {
    showToast('Ảnh chỉ có trong cloud — cần mạng để tải xuống.', 'warning');
    return;
  }

  /* ── iOS: xử lý riêng hoàn toàn miễn phí, không cần iCloud ── */
  if (isIOS()) {
    if (item.type === 'image') {
      showImageViewer(item);
    } else if (item.type === 'file') {
      /* File tài liệu trên iOS: mở tab mới để tải */
      const blob    = dataUrlToBlob(item.content);
      const blobUrl = URL.createObjectURL(blob);
      window.open(blobUrl, '_blank');
      showToast('File đã mở trong tab mới. Nhấn giữ → Tải xuống.', 'info');
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
    } else {
      const text = item.type === 'note'
        ? `${item.title}\n${'─'.repeat(40)}\n\n${item.content}`
        : `${item.title}\n${item.content}`;
      await copyToClipboard(text, item.title);
    }
    return;
  }

  /* ── Android / Desktop: download file bình thường ── */
  try {
    let blob, fileName;

    if (item.type === 'note') {
      blob     = new Blob(
        [`${item.title}\n${'─'.repeat(40)}\n\n${item.content}`],
        { type: 'text/plain;charset=utf-8' }
      );
      fileName = slugify(item.title) + '.txt';

    } else if (item.type === 'image') {
      blob     = dataUrlToBlob(item.content);
      fileName = item.fileName || slugify(item.title) + '.jpg';

    } else if (item.type === 'file') {
      /* Tài liệu: giải mã data URL về blob gốc với đúng MIME type */
      blob     = dataUrlToBlob(item.content);
      fileName = item.fileName || slugify(item.title);

    } else {
      const text = [
        `Tiêu đề : ${item.title}`,
        `URL      : ${item.content}`,
      ].join('\n');
      blob     = new Blob([text], { type: 'text/plain;charset=utf-8' });
      fileName = slugify(item.title) + '.txt';
    }

    const blobUrl = URL.createObjectURL(blob);
    const a       = document.createElement('a');
    a.href         = blobUrl;
    a.download     = fileName;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
    showToast(`Đang tải "${item.title}"...`, 'success');

  } catch (err) {
    console.error('[PSH] Download error:', err);
    showToast('Tải xuống thất bại. Vui lòng thử lại!', 'error');
  }
}

/* Copy text vào clipboard — fallback nếu API không có */
async function copyToClipboard(text, title) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      showToast(`✓ Đã copy "${title}" vào clipboard!`, 'success');
    } else {
      /* Fallback cũ: execCommand (deprecated nhưng vẫn chạy trên Safari cũ) */
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
      document.body.appendChild(ta);
      ta.focus(); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(`✓ Đã copy "${title}" vào clipboard!`, 'success');
    }
  } catch {
    showToast('Không copy được — hãy chọn và copy thủ công.', 'warning');
  }
}

/* Hiện ảnh toàn màn hình để người dùng nhấn giữ → Lưu vào Ảnh (iOS Photos) */
function showImageViewer(item) {
  const overlay = document.createElement('div');
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:99999;
    background:rgba(0,0,0,0.95);
    display:flex;flex-direction:column;
    align-items:center;justify-content:center;gap:16px;
    padding:20px;
  `;

  const hint = document.createElement('p');
  hint.style.cssText = `
    font-family:'Rajdhani',sans-serif;font-size:0.9rem;font-weight:600;
    color:rgba(255,255,255,0.7);text-align:center;letter-spacing:0.05em;
    margin:0;
  `;
  hint.textContent = '👇 Nhấn GIỮ vào ảnh → chọn "Lưu vào Ảnh"';

  const img = document.createElement('img');
  img.src   = item.content;
  img.style.cssText = `
    max-width:100%;max-height:75vh;
    object-fit:contain;border-radius:8px;
    -webkit-touch-callout:default;   /* bật menu nhấn giữ trên iOS */
    touch-action:none;
  `;
  img.alt = item.title;

  const closeBtn = document.createElement('button');
  closeBtn.style.cssText = `
    padding:10px 28px;
    background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.25);
    border-radius:8px;color:#fff;font-size:0.9rem;font-weight:600;
    cursor:pointer;letter-spacing:0.08em;
  `;
  closeBtn.textContent = '✕  ĐÓNG';
  closeBtn.onclick = () => overlay.remove();

  overlay.append(hint, img, closeBtn);
  document.body.appendChild(overlay);

  /* Đóng khi tap vào nền */
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
}

/* ============================================================
   IMAGE HANDLING — Nén ảnh bằng Canvas trước khi lưu
   ============================================================ */

/* Nén ảnh về JPEG tối ưu để tránh vượt giới hạn 1MB của Firestore */
async function compressImage(dataUrl) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const scale  = Math.min(1, IMG_MAX_PX / Math.max(img.width, img.height));
      const canvas = document.createElement('canvas');
      canvas.width  = Math.round(img.width  * scale);
      canvas.height = Math.round(img.height * scale);
      canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
      resolve(canvas.toDataURL('image/jpeg', IMG_QUALITY));
    };
    img.onerror = () => resolve(dataUrl); // fallback nếu không nén được
    img.src = dataUrl;
  });
}

function handleImageFile(file) {
  if (!file || !file.type.startsWith('image/')) {
    showToast('Chỉ hỗ trợ file ảnh (PNG, JPG, GIF, WEBP).', 'warning');
    return;
  }
  if (file.size > 20 * 1024 * 1024) {
    showToast('File quá lớn. Tối đa 20MB.', 'error');
    return;
  }

  const reader = new FileReader();
  reader.onload = async e => {
    showToast('Đang nén ảnh...', 'info');
    const compressed       = await compressImage(e.target.result);
    state.imageBase64      = compressed;
    state.imageFileName    = file.name.replace(/\.[^.]+$/, '') + '.jpg';

    $('imagePreviewEl').src = compressed;
    $('imagePreviewWrap').classList.remove('hidden');
    $('dropZoneContent').classList.add('hidden');

    const titleEl = $('imageTitle');
    if (titleEl && !titleEl.value) titleEl.value = file.name.replace(/\.[^.]+$/, '');

    const kb = Math.round(compressed.length * 0.75 / 1024);
    showToast(`Ảnh đã nén: ~${kb} KB`, 'success');
  };
  reader.readAsDataURL(file);
}

/* ============================================================
   FILE (TÀI LIỆU) HANDLING
   ============================================================ */
const FILE_MAX_BYTES = 700 * 1024; // 700 KB — giữ document Firestore < 1 MB

/* Trả về icon + màu theo loại file */
function getFileIconInfo(mimeType, fileName) {
  const ext  = (fileName || '').split('.').pop().toLowerCase();
  const mime = mimeType || '';
  if (mime.includes('pdf')         || ext === 'pdf')
    return { icon: 'fa-file-pdf',        color: '#ff453a' };
  if (mime.includes('word')        || ['doc','docx'].includes(ext))
    return { icon: 'fa-file-word',       color: '#2b7fff' };
  if (mime.includes('excel') || mime.includes('spreadsheet') || ['xls','xlsx','csv'].includes(ext))
    return { icon: 'fa-file-excel',      color: '#30d158' };
  if (mime.includes('powerpoint')  || ['ppt','pptx'].includes(ext))
    return { icon: 'fa-file-powerpoint', color: '#ff9f0a' };
  if (['zip','rar','7z','tar','gz'].includes(ext))
    return { icon: 'fa-file-zipper',     color: '#bf5af2' };
  if (mime.includes('text') || ['txt','md','log'].includes(ext))
    return { icon: 'fa-file-lines',      color: '#98989e' };
  if (mime.includes('audio')       || ['mp3','wav','aac'].includes(ext))
    return { icon: 'fa-file-audio',      color: '#30d158' };
  if (mime.includes('video')       || ['mp4','mov','avi'].includes(ext))
    return { icon: 'fa-file-video',      color: '#ff453a' };
  return { icon: 'fa-file',             color: '#98989e' };
}

function formatFileSize(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function handleDocumentFile(file) {
  if (!file) return;

  if (file.size > FILE_MAX_BYTES) {
    showToast(
      `File quá lớn (${formatFileSize(file.size)}). Tối đa ${formatFileSize(FILE_MAX_BYTES)}.`,
      'error'
    );
    return;
  }

  const reader = new FileReader();
  reader.onload = e => {
    state.docBase64    = e.target.result;  // data:<mime>;base64,...
    state.docFileName  = file.name;
    state.docMimeType  = file.type;
    state.docFileSize  = file.size;

    /* Cập nhật UI trong modal */
    const info = getFileIconInfo(file.type, file.name);
    $('docSelectedIcon').className = `fas ${info.icon} doc-selected-icon`;
    $('docSelectedIcon').style.color = info.color;
    $('docSelectedName').textContent = file.name;
    $('docSelectedSize').textContent = formatFileSize(file.size);
    $('docSelectedWrap').classList.remove('hidden');
    $('docDropContent').classList.add('hidden');

    /* Tự điền tên nếu trống */
    const titleEl = $('fileTitle');
    if (titleEl && !titleEl.value) {
      titleEl.value = file.name.replace(/\.[^.]+$/, '');
    }
  };
  reader.readAsDataURL(file);
}

/* ============================================================
   MODAL — Thêm mục mới
   ============================================================ */
function openAddModal(type) {
  state.pendingItemType = type;
  state.imageBase64 = null; state.imageFileName = null;
  state.docBase64   = null; state.docFileName   = null;
  state.docMimeType = null; state.docFileSize   = 0;

  ['noteForm','imageForm','linkForm','fileForm'].forEach(id => hide($(id)));
  ['noteTitle','noteContent','imageTitle','linkTitle','linkUrl','linkDesc','fileTitle'].forEach(id => {
    const el = $(id); if (el) el.value = '';
  });
  $('imagePreviewWrap')?.classList.add('hidden');
  $('dropZoneContent')?.classList.remove('hidden');
  $('imageFile').value = '';
  $('docSelectedWrap')?.classList.add('hidden');
  $('docDropContent')?.classList.remove('hidden');
  if ($('docFile')) $('docFile').value = '';

  const cfg = {
    note:  { title: 'THÊM GHI CHÚ',   icon: 'fa-file-lines',    formId: 'noteForm',  focus: 'noteTitle' },
    image: { title: 'THÊM HÌNH ẢNH',  icon: 'fa-image',          formId: 'imageForm', focus: 'imageTitle' },
    link:  { title: 'THÊM LIÊN KẾT',  icon: 'fa-link',           formId: 'linkForm',  focus: 'linkTitle' },
    file:  { title: 'THÊM TÀI LIỆU',  icon: 'fa-file-arrow-up',  formId: 'fileForm',  focus: 'fileTitle' },
  }[type];

  $('modalTitle').textContent = cfg.title;
  $('modalTypeIcon').className = `fas ${cfg.icon} modal-title-icon`;
  show($(cfg.formId));
  show($('addItemModal'));
  setTimeout(() => $(cfg.focus)?.focus(), 100);
}

/* Mở modal để chỉnh sửa một mục đã có */
function openEditModal(itemId) {
  const item = state.items.find(i => i.id === itemId);
  if (!item) return;

  state.editingItemId   = itemId;
  state.pendingItemType = item.type;
  state.imageBase64     = item.type === 'image' ? item.content : null;
  state.imageFileName   = item.fileName || null;

  // Reset tất cả form trước
  ['noteForm','imageForm','linkForm'].forEach(id => hide($(id)));
  ['noteTitle','noteContent','imageTitle','linkTitle','linkUrl','linkDesc'].forEach(id => {
    const el = $(id); if (el) el.value = '';
  });

  // Điền dữ liệu hiện tại vào form
  if (item.type === 'note') {
    $('noteTitle').value   = item.title;
    $('noteContent').value = item.content;
    show($('noteForm'));
    setTimeout(() => $('noteTitle')?.focus(), 100);

  } else if (item.type === 'image') {
    $('imageTitle').value = item.title;
    // Hiển thị preview ảnh hiện tại
    if (item.content && item.content !== '[cached]') {
      $('imagePreviewEl').src = item.content;
      $('imagePreviewWrap').classList.remove('hidden');
      $('dropZoneContent').classList.add('hidden');
    } else {
      $('imagePreviewWrap').classList.add('hidden');
      $('dropZoneContent').classList.remove('hidden');
    }
    show($('imageForm'));
    setTimeout(() => $('imageTitle')?.focus(), 100);

  } else if (item.type === 'link') {
    $('linkTitle').value = item.title;
    $('linkUrl').value   = item.content;
    $('linkDesc').value  = item.description || '';
    show($('linkForm'));
    setTimeout(() => $('linkTitle')?.focus(), 100);
  }

  // Đổi tiêu đề và icon modal sang màu tím (edit mode)
  const typeIcon = { note:'fa-pen-to-square', image:'fa-image', link:'fa-pen-to-square' }[item.type];
  $('modalTitle').textContent     = 'CHỈNH SỬA';
  $('modalTypeIcon').className    = `fas ${typeIcon} modal-title-icon`;
  $('modalTypeIcon').style.color  = 'var(--purple)';
  $('modalTypeIcon').style.filter = 'drop-shadow(0 0 6px var(--purple))';

  show($('addItemModal'));
}

function closeAddModal() {
  hide($('addItemModal'));
  state.pendingItemType = null;
  state.editingItemId   = null;
  // Reset màu icon về mặc định
  $('modalTypeIcon').style.color  = '';
  $('modalTypeIcon').style.filter = '';
}

/* Guard chống gọi saveItem 2 lần liên tiếp (double-click hoặc Enter+Click) */
let _isSaving = false;

async function saveItem() {
  if (_isSaving) return;
  _isSaving = true;

  try {
    const type = state.pendingItemType;
    let title, content, description, fileName;

    if (type === 'note') {
      title   = $('noteTitle').value.trim();
      content = $('noteContent').value.trim();
      if (!title)   { shakeEl($('noteTitle'));   showToast('Nhập tiêu đề!', 'warning'); return; }
      if (!content) { shakeEl($('noteContent')); showToast('Nhập nội dung!', 'warning'); return; }

    } else if (type === 'image') {
      title    = $('imageTitle').value.trim();
      if (!title)             { shakeEl($('imageTitle')); showToast('Nhập tên ảnh!', 'warning'); return; }
      if (!state.imageBase64) { showToast('Chọn một ảnh!', 'warning'); return; }
      content  = state.imageBase64;
      fileName = state.imageFileName;

    } else if (type === 'link') {
      title       = $('linkTitle').value.trim();
      content     = $('linkUrl').value.trim();
      description = $('linkDesc').value.trim();
      if (!title)               { shakeEl($('linkTitle')); showToast('Nhập tên liên kết!', 'warning'); return; }
      if (!content)             { shakeEl($('linkUrl'));   showToast('Nhập địa chỉ URL!', 'warning'); return; }
      if (!isValidUrl(content)) { shakeEl($('linkUrl'));   showToast('URL không hợp lệ! Cần bắt đầu bằng http:// hoặc https://', 'warning'); return; }

    } else if (type === 'file') {
      title    = $('fileTitle').value.trim();
      if (!title)             { shakeEl($('fileTitle')); showToast('Nhập tên tài liệu!', 'warning'); return; }
      if (!state.docBase64)   { showToast('Chưa chọn file!', 'warning'); return; }
      content  = state.docBase64;
      fileName = state.docFileName;
      description = `${state.docMimeType || ''}|${state.docFileSize || 0}`;
    }

    /* ── CHẾ ĐỘ SỬA ── */
    if (state.editingItemId) {
      const idx = state.items.findIndex(i => i.id === state.editingItemId);
      if (idx === -1) { closeAddModal(); return; }

      const existing    = state.items[idx];
      existing.title    = title;
      existing.updatedAt = Date.now();

      if (type === 'note') {
        existing.content = content;
      } else if (type === 'image') {
        if (state.imageBase64 && state.imageBase64 !== existing.content) {
          existing.content  = state.imageBase64;
          existing.fileName = state.imageFileName || existing.fileName;
        }
      } else if (type === 'link') {
        existing.content     = content;
        existing.description = description || '';
      }

      closeAddModal();
      persistItem(existing);
      showToast(`Đã cập nhật "${title}"!`, 'success');
      return;
    }

    /* ── CHẾ ĐỘ THÊM MỚI ── */
    const newItem = {
      id:          generateId(),
      type,
      title,
      content,
      description: description || '',
      fileName:    fileName || '',
      createdAt:   Date.now(),
      updatedAt:   Date.now(),
      inTrash:     false,
      trashedAt:   null,
    };

    state.items.unshift(newItem);
    closeAddModal();
    persistItem(newItem);
    if (state.currentSection !== 'dashboard') switchSection('dashboard');
    showToast(`Đã thêm "${title}"!`, 'success');

  } finally {
    /* Luôn reset flag dù thành công, validation fail hay lỗi bất ngờ */
    _isSaving = false;
  }
}

/* ============================================================
   RENDER — Vẽ giao diện
   ============================================================ */
function renderAll() {
  renderDashboard();
  renderTrash();
  updateTrashBadge();
}

function renderDashboard() {
  const grid  = $('itemsGrid');
  const empty = $('emptyState');
  const q     = state.searchQuery.toLowerCase();

  let items = state.items.filter(i => !i.inTrash);
  if (state.currentFilter !== 'all') items = items.filter(i => i.type === state.currentFilter);
  if (q) items = items.filter(i =>
    i.title.toLowerCase().includes(q) ||
    (i.type === 'note' && i.content?.toLowerCase().includes(q)) ||
    (i.description?.toLowerCase().includes(q))
  );
  items.sort((a, b) => b.createdAt - a.createdAt);

  grid.innerHTML = '';
  if (!items.length) {
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
    items.forEach(item => grid.appendChild(createCard(item, false)));
  }
  $('itemCountText').textContent = `${items.length} mục`;
}

function renderTrash() {
  const grid  = $('trashGrid');
  const empty = $('trashEmptyState');
  const items = state.items.filter(i => i.inTrash).sort((a, b) => b.trashedAt - a.trashedAt);

  grid.innerHTML = '';
  if (!items.length) {
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
    items.forEach(item => grid.appendChild(createCard(item, true)));
  }
}

function updateTrashBadge() {
  const count = state.items.filter(i => i.inTrash).length;
  $('trashBadge').textContent = count;
  $('trashBadge').classList.toggle('hidden', count === 0);
}

/* ============================================================
   CARD — Tạo thẻ dữ liệu
   ============================================================ */
function createCard(item, isTrash) {
  const card = document.createElement('div');
  card.className = `item-card card-type-${item.type}`;
  card.dataset.id = item.id;

  const typeLabel = { note:'GHI CHÚ', image:'HÌNH ẢNH', link:'LIÊN KẾT', file:'TÀI LIỆU' }[item.type];
  const typeIcon  = { note:'fa-file-lines', image:'fa-image', link:'fa-link', file:'fa-file-arrow-up' }[item.type];
  const dateStr   = formatDate(isTrash ? item.trashedAt : item.createdAt);

  let contentHtml = '';
  if (item.type === 'note') {
    contentHtml = `<p class="card-note-content">${escHtml(item.content)}</p>`;
  } else if (item.type === 'file') {
    /* Tài liệu: icon theo loại + tên file + kích thước */
    const [mime, sizeStr] = (item.description || '|0').split('|');
    const fileSize = parseInt(sizeStr) || 0;
    const info = getFileIconInfo(mime, item.fileName || item.title);
    contentHtml = `
      <div class="card-file-body">
        <i class="fas ${info.icon} card-file-icon" style="color:${info.color}"></i>
        <div class="card-file-meta">
          <span class="card-file-name">${escHtml(item.fileName || item.title)}</span>
          <span class="card-file-size">${fileSize ? formatFileSize(fileSize) : '—'}</span>
        </div>
      </div>`;
  } else if (item.type === 'image') {
    /* Nếu content là placeholder '[cached]', hiện icon thay thế */
    if (item.content === '[cached]') {
      contentHtml = `<div class="card-image-wrap" style="display:flex;align-items:center;justify-content:center;min-height:100px;color:var(--text-dim)"><i class="fas fa-cloud" style="font-size:2rem"></i></div>`;
    } else {
      contentHtml = `<div class="card-image-wrap"><img class="card-image" src="${item.content}" alt="${escHtml(item.title)}" loading="lazy"></div>`;
    }
  } else {
    const safeUrl = sanitizeUrl(item.content);
    contentHtml = `
      <a class="card-link-url" href="${safeUrl}" target="_blank" rel="noopener noreferrer">
        <i class="fas fa-arrow-up-right-from-square"></i>${escHtml(item.content)}
      </a>
      ${item.description ? `<p class="card-link-desc">${escHtml(item.description)}</p>` : ''}`;
  }

  const footerHtml = isTrash
    ? `<div class="trash-card-actions">
         <button class="btn-restore"     data-id="${item.id}"><i class="fas fa-rotate-left"></i> Khôi Phục</button>
         <button class="btn-perm-delete" data-id="${item.id}"><i class="fas fa-fire"></i> Xóa Vĩnh Viễn</button>
       </div>
       <span class="card-date">Xóa: ${dateStr}</span>`
    : `<span class="card-date">${dateStr}</span>`;

  const menuHtml = isTrash ? '' : `
    <div style="position:relative">
      <button class="card-menu-btn" data-id="${item.id}" title="Tùy chọn">
        <i class="fas fa-ellipsis-vertical"></i>
      </button>
    </div>`;

  card.innerHTML = `
    <div class="card-accent-bar"></div>
    <div class="card-body">
      <div class="card-header-row">
        <span class="card-type-badge"><i class="fas ${typeIcon}"></i> ${typeLabel}</span>
        ${menuHtml}
      </div>
      <h3 class="card-title">${escHtml(item.title)}</h3>
      ${contentHtml}
    </div>
    <div class="card-footer">${footerHtml}</div>`;

  if (!isTrash) {
    card.querySelector('.card-menu-btn')
      ?.addEventListener('click', e => { e.stopPropagation(); openCardMenu(item.id, e.currentTarget); });
  } else {
    card.querySelector('.btn-restore')?.addEventListener('click', () => restoreItem(item.id));
    card.querySelector('.btn-perm-delete')?.addEventListener('click', () => confirmDeletePermanent(item.id));
  }
  return card;
}

function openCardMenu(itemId, btnEl) {
  document.querySelectorAll('.card-menu-dropdown').forEach(d => d.remove());

  const item = state.items.find(i => i.id === itemId);
  const canEdit = item && item.type !== 'image'; // Ảnh chỉ edit tên, cũng hỗ trợ

  const dropdown = document.createElement('div');
  dropdown.className = 'card-menu-dropdown';
  dropdown.innerHTML = `
    <button class="dropdown-item edit" data-a="edit"><i class="fas fa-pen-to-square"></i> Chỉnh Sửa</button>
    <button class="dropdown-item" data-a="download"><i class="fas fa-download"></i> Tải Xuống</button>
    <div class="dropdown-divider"></div>
    <button class="dropdown-item" data-a="trash"><i class="fas fa-trash-can"></i> Chuyển Vào Thùng Rác</button>
    <button class="dropdown-item danger" data-a="delete"><i class="fas fa-fire"></i> Xóa Vĩnh Viễn</button>`;

  btnEl.parentElement.appendChild(dropdown);
  dropdown.querySelector('[data-a="edit"]')    .addEventListener('click', () => { openEditModal(itemId);         dropdown.remove(); });
  dropdown.querySelector('[data-a="download"]').addEventListener('click', () => { downloadItem(itemId);          dropdown.remove(); });
  dropdown.querySelector('[data-a="trash"]')   .addEventListener('click', () => { moveToTrash(itemId);           dropdown.remove(); });
  dropdown.querySelector('[data-a="delete"]')  .addEventListener('click', () => { dropdown.remove(); confirmDeletePermanent(itemId); });

  const handler = e => {
    if (!dropdown.contains(e.target) && e.target !== btnEl) {
      dropdown.remove();
      document.removeEventListener('click', handler);
    }
  };
  setTimeout(() => document.addEventListener('click', handler), 0);
}

/* ============================================================
   LOCK SCREEN — Setup & Login
   ============================================================ */
function initLockScreen() {
  const hasPass  = isPasswordSet();
  const authMode = getAuthMode();

  if (!hasPass && USE_FIREBASE) {
    /* ── THIẾT BỊ MỚI + Firebase ──
       Hiện Login thay vì Setup: người dùng nhập mật khẩu cũ để đồng bộ cloud */
    $('lockSubtitle').textContent = 'NHẬP MẬT KHẨU ĐỂ ĐỒNG BỘ';
    hide($('setupForm'));
    show($('loginForm'));
    show($('newDeviceActions'));
    $('loginFormLabel').textContent = 'ĐĂNG NHẬP / THIẾT BỊ MỚI';
    showLoginMode('password');

    /* Banner hướng dẫn — chỉ chèn 1 lần */
    if (!$('loginForm').querySelector('.new-device-banner')) {
      const banner = document.createElement('div');
      banner.className = 'new-device-banner';
      banner.innerHTML = `<i class="fas fa-mobile-screen-button"></i>
        <span>Thiết bị mới — nhập <strong>mật khẩu hiện tại</strong> để đồng bộ dữ liệu từ cloud. Chưa có tài khoản? Nhấn "Tạo kho mới".</span>`;
      $('loginFormLabel').insertAdjacentElement('afterend', banner);
    }

    $('lockStatusText').textContent = 'NEW DEVICE';

  } else if (!hasPass) {
    /* ── LẦN ĐẦU, không Firebase ── */
    $('lockSubtitle').textContent = 'THIẾT LẬP LẦN ĐẦU';
    show($('setupForm'));
    hide($('loginForm'));
    $('lockStatusText').textContent = 'SETUP REQUIRED';

  } else {
    /* ── ĐĂNG NHẬP BÌNH THƯỜNG ── */
    $('lockSubtitle').textContent = 'XÁC THỰC ĐỂ TRUY CẬP';
    hide($('setupForm'));
    show($('loginForm'));
    hide($('newDeviceActions'));
    showLoginMode(authMode);
    $('loginFormLabel').textContent = authMode === 'pin' ? 'NHẬP PIN 6 SỐ' : 'NHẬP MẬT KHẨU';
    $('lockStatusText').textContent = 'SYSTEM LOCKED';
  }

  setLoginBusy(false);
}

function showLoginMode(mode) {
  const stored = getAuthMode();
  if (mode === 'pin') {
    show($('loginPinSection'));
    hide($('loginPasswordSection'));
    $('switchToPasswordBtn').style.display = '';
  } else {
    hide($('loginPinSection'));
    show($('loginPasswordSection'));
    $('switchToPinBtn').style.display = stored === 'pin' ? '' : 'none';
  }
}

function setLoginBusy(busy) {
  const btn = $('loginPasswordBtn');
  if (btn) {
    btn.disabled = busy;
    btn.innerHTML = busy
      ? '<i class="fas fa-spinner fa-spin"></i> ĐANG XỬ LÝ...'
      : '<i class="fas fa-sign-in-alt"></i> TRUY CẬP';
  }
  const sb = $('setupBtn');
  if (sb) sb.disabled = busy;
}

function showLoginError(msg) {
  const el = $('loginError');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function showSetupError(msg) {
  const el = $('setupError');
  el.textContent = msg;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 4000);
}

function resetLoginPin() {
  state.loginPinBuffer = '';
  updatePinDisplay('login', 0);
}

function shakePinDisplay(displayId) {
  const el = $(displayId);
  if (!el) return;
  el.querySelectorAll('.pin-dot').forEach(d => d.classList.add('error'));
  el.classList.add('pin-shake');
  setTimeout(() => {
    el.classList.remove('pin-shake');
    el.querySelectorAll('.pin-dot').forEach(d => d.classList.remove('error','filled'));
  }, 600);
}

function handleSetupPinKey(key) {
  const buf = state.setupPinBuffer;
  if      (key === 'back')  state.setupPinBuffer = buf.slice(0, -1);
  else if (key === 'clear') state.setupPinBuffer = '';
  else if (buf.length < 6)  state.setupPinBuffer += key;
  updatePinDisplay('setup', state.setupPinBuffer.length);

  if (state.setupPinBuffer.length === 6) {
    setTimeout(async () => {
      state.setupMode = 'pin';
      await setupPassword(state.setupPinBuffer);
      state.setupPinBuffer = '';
      updatePinDisplay('setup', 0);
      initLockScreen();
      showToast('PIN đã thiết lập thành công!', 'success');
    }, 200);
  }
}

function handleLoginPinKey(key) {
  if (state.lockedUntil > Date.now()) return;
  const buf = state.loginPinBuffer;
  if      (key === 'back')  state.loginPinBuffer = buf.slice(0, -1);
  else if (key === 'clear') state.loginPinBuffer = '';
  else if (buf.length < 6)  state.loginPinBuffer += key;
  updatePinDisplay('login', state.loginPinBuffer.length);
  if (state.loginPinBuffer.length === 6) setTimeout(() => attemptLogin(state.loginPinBuffer), 200);
}

function updatePinDisplay(ctx, count) {
  const id   = ctx === 'setup' ? 'setupPinDisplay' : 'loginPinDisplay';
  const dots = document.querySelectorAll(`#${id} .pin-dot`);
  dots.forEach((d, i) => { d.classList.toggle('filled', i < count); d.classList.remove('error'); });
}

/* ============================================================
   AUTO-LOCK
   ============================================================ */
function startAutoLock() {
  stopAutoLock();
  state.autoLockEndTime = Date.now() + AUTO_LOCK_MS;
  state.timerInterval   = setInterval(tickAutoLock, 1000);
  tickAutoLock();
  ['mousemove','mousedown','keydown','touchstart','scroll','click'].forEach(ev =>
    document.addEventListener(ev, resetAutoLock, { passive: true })
  );
}

function stopAutoLock() {
  if (state.timerInterval) { clearInterval(state.timerInterval); state.timerInterval = null; }
  ['mousemove','mousedown','keydown','touchstart','scroll','click'].forEach(ev =>
    document.removeEventListener(ev, resetAutoLock)
  );
}

function resetAutoLock() {
  if (!state.isLocked) state.autoLockEndTime = Date.now() + AUTO_LOCK_MS;
}

function tickAutoLock() {
  const left = Math.max(0, state.autoLockEndTime - Date.now());
  const el   = $('autoLockTimer');
  const wrap = $('autoLockDisplay');
  if (el) {
    el.textContent = `${String(Math.floor(left/60000)).padStart(2,'0')}:${String(Math.floor((left%60000)/1000)).padStart(2,'0')}`;
  }
  if (wrap) {
    wrap.classList.toggle('warning',  left <= WARN_THRESHOLD && left > 30000);
    wrap.classList.toggle('critical', left <= 30000);
  }
  if (left === 0) lockApp();
}

/* ============================================================
   CALCULATOR
   ============================================================ */
function toggleCalc() {
  state.calcVisible = !state.calcVisible;
  $('calcWidget').classList.toggle('hidden', !state.calcVisible);
  /* Thêm class calc-open vào body để ẩn FAB khi máy tính mở trên mobile */
  document.body.classList.toggle('calc-open', state.calcVisible);
}

function handleCalcInput(action) {
  const c = state.calc;

  if (!isNaN(action) || action === 'decimal') {
    const digit = action === 'decimal' ? '.' : action;
    if (c.waitingInput || c.justCalc) {
      c.display = digit === '.' ? '0.' : digit;
      c.waitingInput = false;
      c.justCalc     = false;
    } else {
      if (digit === '.' && c.display.includes('.')) return;
      if (c.display.length >= 16) return;
      c.display = c.display === '0' && digit !== '.' ? digit : c.display + digit;
    }
    updateCalcDisplay(); return;
  }

  if (action === 'clear') {
    Object.assign(c, { display:'0', history:'', accumulator:null, operator:null, waitingInput:false, justCalc:false });
    document.querySelectorAll('.op-btn').forEach(b => b.classList.remove('active'));
    updateCalcDisplay(); return;
  }

  if (action === 'sign') {
    const n = parseFloat(c.display);
    if (!isNaN(n)) { c.display = String(-n); updateCalcDisplay(); } return;
  }

  if (action === 'percent') {
    const n = parseFloat(c.display);
    if (!isNaN(n)) { c.display = String(n / 100); updateCalcDisplay(); } return;
  }

  const opMap = { add:'+', subtract:'−', multiply:'×', divide:'÷' };

  if (opMap[action]) {
    const cur = parseFloat(c.display);
    if (c.operator && !c.waitingInput && !c.justCalc) {
      const r = calcDo(c.accumulator, c.operator, cur);
      c.accumulator = r; c.display = fmtNum(r);
    } else { c.accumulator = cur; }
    c.operator = action; c.waitingInput = true; c.justCalc = false;
    c.history = `${fmtNum(c.accumulator)} ${opMap[action]}`;
    document.querySelectorAll('.op-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.op-btn[data-action="${action}"]`)?.classList.add('active');
    updateCalcDisplay(); return;
  }

  if (action === 'equals' && c.operator && c.accumulator !== null) {
    const cur = parseFloat(c.display);
    const r   = calcDo(c.accumulator, c.operator, cur);
    c.history = `${fmtNum(c.accumulator)} ${opMap[c.operator]} ${fmtNum(cur)} =`;
    c.display = fmtNum(r); c.accumulator = null; c.operator = null;
    c.justCalc = true; c.waitingInput = false;
    document.querySelectorAll('.op-btn').forEach(b => b.classList.remove('active'));
    updateCalcDisplay();
  }
}

function calcDo(a, op, b) {
  const r = { add: a+b, subtract: a-b, multiply: a*b, divide: b ? a/b : null }[op];
  if (r === null) { showToast('Không thể chia cho 0!', 'error'); return 0; }
  return r ?? b;
}

function fmtNum(n) {
  if (!isFinite(n) || isNaN(n)) return 'Lỗi';
  const s = String(parseFloat(n.toPrecision(12)));
  return s.length > 14 ? n.toExponential(6) : s;
}

function updateCalcDisplay() {
  const el = $('calcDisplay'); if (!el) return;
  el.textContent = state.calc.display;
  const hl = $('calcHistory'); if (hl) hl.textContent = state.calc.history;
  const len = state.calc.display.length;
  el.style.fontSize = len > 12 ? '1.1rem' : len > 9 ? '1.6rem' : '2rem';
}

/* ============================================================
   NAVIGATION
   ============================================================ */
function switchSection(section) {
  state.currentSection = section;
  document.querySelectorAll('.nav-item[data-section]').forEach(el =>
    el.classList.toggle('active', el.dataset.section === section)
  );
  const isDash = section === 'dashboard';
  $('dashboardSection').classList.toggle('active', isDash);
  $('dashboardSection').classList.toggle('hidden', !isDash);
  $('trashSection').classList.toggle('active', !isDash);
  $('trashSection').classList.toggle('hidden', isDash);

  const labels = {
    dashboard: { icon: 'fa-microchip', title: 'DASHBOARD' },
    trash:     { icon: 'fa-trash-can', title: 'THÙNG RÁC' },
  };
  const cfg = labels[section] || labels.dashboard;
  $('breadcrumbIcon').className   = `fas ${cfg.icon}`;
  $('breadcrumbTitle').textContent = cfg.title;
  $('fabContainer').style.display  = isDash ? '' : 'none';
  closeMobileSidebar();
}

const openMobileSidebar  = () => { $('sidebar').classList.add('mobile-open'); $('sidebarOverlay').classList.remove('hidden'); };
const closeMobileSidebar = () => { $('sidebar').classList.remove('mobile-open'); $('sidebarOverlay').classList.add('hidden'); };

/* ============================================================
   CONFIRM / TOAST
   ============================================================ */
function showConfirm(title, message, onOk) {
  $('confirmModalTitle').textContent = title;
  $('confirmModalMsg').innerHTML = message;
  state.confirmCb = onOk;
  show($('confirmModal'));
}
const closeConfirm = () => { hide($('confirmModal')); state.confirmCb = null; };

function showToast(msg, type = 'info') {
  const icons = { success:'fa-circle-check', error:'fa-circle-xmark', info:'fa-circle-info', warning:'fa-triangle-exclamation' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${escHtml(msg)}`;
  $('toastContainer').appendChild(toast);
  setTimeout(() => { toast.classList.add('hiding'); setTimeout(() => toast.remove(), 300); }, 3500);
}

/* ============================================================
   PARTICLES — Hiệu ứng hạt trên màn hình khóa
   ============================================================ */
function initParticles() {
  const canvas = $('particleCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
  resize();
  window.addEventListener('resize', resize);

  const pts = Array.from({ length: 60 }, () => ({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    r: Math.random() * 1.5 + 0.3,
    vx: (Math.random() - 0.5) * 0.35,
    vy: -(Math.random() * 0.5 + 0.15),
    a: Math.random(),
  }));

  (function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    pts.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,245,255,${p.a * 0.5})`;
      ctx.fill();
      p.x += p.vx; p.y += p.vy;
      p.a += (Math.random() - 0.5) * 0.02;
      p.a  = Math.max(0.05, Math.min(1, p.a));
      if (p.y < -5)              p.y = canvas.height + 5;
      if (p.x < -5)              p.x = canvas.width  + 5;
      if (p.x > canvas.width+5)  p.x = -5;
    });
    requestAnimationFrame(draw);
  })();
}

/* ============================================================
   UTILITIES
   ============================================================ */
const $ = id => document.getElementById(id);
const show = el => el?.classList.remove('hidden');
const hide = el => el?.classList.add('hidden');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const generateId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 9);

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
}

function sanitizeUrl(url) {
  try {
    const u = new URL(url);
    return (u.protocol === 'http:' || u.protocol === 'https:') ? url : '#';
  } catch { return '#'; }
}

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

const slugify = str =>
  (str||'file').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,50)||'file';

function formatDate(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleDateString('vi-VN', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

function shakeEl(el) {
  if (!el) return;
  el.style.animation = 'none';
  void el.offsetHeight;
  el.style.animation = 'pinShake 0.4s ease';
  setTimeout(() => { el.style.animation = ''; }, 400);
}

/* ============================================================
   EVENT LISTENERS
   ============================================================ */
function setupEvents() {
  /* ── LOCK SCREEN ── */
  $('modePasswordBtn').addEventListener('click', () => {
    state.setupMode = 'password';
    $('modePasswordBtn').classList.add('active');
    $('modePinBtn').classList.remove('active');
    show($('setupPasswordSection')); hide($('setupPinSection'));
    state.setupPinBuffer = ''; updatePinDisplay('setup', 0);
  });

  $('modePinBtn').addEventListener('click', () => {
    state.setupMode = 'pin';
    $('modePinBtn').classList.add('active');
    $('modePasswordBtn').classList.remove('active');
    hide($('setupPasswordSection')); show($('setupPinSection'));
    $('setupPassword').value = ''; $('setupConfirm').value = '';
  });

  document.querySelectorAll('#setupPinSection .pin-key').forEach(b =>
    b.addEventListener('click', () => handleSetupPinKey(b.dataset.key))
  );

  $('setupBtn').addEventListener('click', async () => {
    if (state.setupMode === 'pin') return;
    const pw = $('setupPassword').value, cfm = $('setupConfirm').value;
    if (pw.length < 4) { showSetupError('Mật khẩu ít nhất 4 ký tự.'); return; }
    if (pw !== cfm)    { showSetupError('Mật khẩu xác nhận không khớp!'); return; }
    setLoginBusy(true);
    await sleep(50);
    await setupPassword(pw);
    $('setupPassword').value = ''; $('setupConfirm').value = '';
    initLockScreen();
    showToast('Mật khẩu đã thiết lập!', 'success');
  });

  [$('setupPassword'), $('setupConfirm')].forEach(el =>
    el?.addEventListener('keydown', e => { if (e.key === 'Enter') $('setupBtn').click(); })
  );

  document.querySelectorAll('#loginPinSection .pin-key').forEach(b =>
    b.addEventListener('click', () => handleLoginPinKey(b.dataset.key))
  );

  $('loginPasswordBtn').addEventListener('click', () => {
    const pw = $('loginPassword').value;
    if (!pw) { showLoginError('Nhập mật khẩu!'); return; }
    attemptLogin(pw);
  });

  $('loginPassword').addEventListener('keydown', e => {
    if (e.key === 'Enter') $('loginPasswordBtn').click();
  });

  $('switchToPasswordBtn').addEventListener('click', () => {
    resetLoginPin(); hide($('loginError')); showLoginMode('password');
  });
  $('switchToPinBtn').addEventListener('click', () => {
    if ($('loginPassword')) $('loginPassword').value = '';
    hide($('loginError')); showLoginMode('pin');
  });

  /* Nút "Tạo kho mới" trên form thiết bị mới */
  $('goToSetupBtn').addEventListener('click', () => {
    hide($('loginForm'));
    show($('setupForm'));
    show($('backToLoginBtn'));
    $('lockSubtitle').textContent = 'TẠO MẬT KHẨU MỚI';
    $('lockStatusText').textContent = 'SETUP';
  });

  /* Nút "Đã có mật khẩu" — quay lại login */
  $('backToLoginBtn').addEventListener('click', () => {
    hide($('setupForm'));
    initLockScreen(); // Khởi lại để hiện đúng trạng thái
  });

  document.querySelectorAll('.toggle-pw-btn').forEach(btn =>
    btn.addEventListener('click', () => {
      const input = $(btn.dataset.target);
      if (!input) return;
      const v = input.type === 'password';
      input.type = v ? 'text' : 'password';
      btn.querySelector('i').className = v ? 'fas fa-eye-slash' : 'fas fa-eye';
    })
  );

  /* ── APP NAVIGATION ── */
  $('sidebarCollapseBtn').addEventListener('click', () => $('sidebar').classList.toggle('collapsed'));
  $('hamburgerBtn').addEventListener('click', () =>
    $('sidebar').classList.contains('mobile-open') ? closeMobileSidebar() : openMobileSidebar()
  );
  $('sidebarOverlay').addEventListener('click', closeMobileSidebar);

  document.querySelectorAll('.nav-item[data-section]').forEach(el =>
    el.addEventListener('click', e => { e.preventDefault(); switchSection(el.dataset.section); })
  );
  $('lockBtn').addEventListener('click', lockApp);

  /* ── HEADER ── */
  $('searchInput').addEventListener('input', () => {
    state.searchQuery = $('searchInput').value;
    $('searchClear').classList.toggle('hidden', !state.searchQuery);
    renderDashboard();
  });
  $('searchClear').addEventListener('click', () => {
    $('searchInput').value = ''; state.searchQuery = '';
    $('searchClear').classList.add('hidden'); renderDashboard();
  });
  $('headerCalcBtn').addEventListener('click', toggleCalc);

  /* ── FILTER TABS ── */
  document.querySelectorAll('.filter-tab').forEach(tab =>
    tab.addEventListener('click', () => {
      document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.currentFilter = tab.dataset.filter;
      renderDashboard();
    })
  );

  /* ── FAB ── */
  $('fabMain').addEventListener('click', () => {
    state.fabOpen = !state.fabOpen;
    $('fabMain').classList.toggle('open', state.fabOpen);
    $('fabOptions').classList.toggle('hidden', !state.fabOpen);
  });
  document.querySelectorAll('.fab-option').forEach(btn =>
    btn.addEventListener('click', () => {
      state.fabOpen = false;
      $('fabMain').classList.remove('open'); $('fabOptions').classList.add('hidden');
      openAddModal(btn.dataset.type);
    })
  );
  document.addEventListener('click', e => {
    if (state.fabOpen && !$('fabContainer').contains(e.target)) {
      state.fabOpen = false;
      $('fabMain').classList.remove('open'); $('fabOptions').classList.add('hidden');
    }
    if (!e.target.closest('.card-menu-btn') && !e.target.closest('.card-menu-dropdown')) {
      document.querySelectorAll('.card-menu-dropdown').forEach(d => d.remove());
    }
  });

  /* ── CALCULATOR ── */
  $('calcToggleBtn').addEventListener('click', toggleCalc);
  $('calcClose').addEventListener('click',    () => { state.calcVisible = false; $('calcWidget').classList.add('hidden'); document.body.classList.remove('calc-open'); });
  $('calcMinimize').addEventListener('click', () => { state.calcVisible = false; $('calcWidget').classList.add('hidden'); document.body.classList.remove('calc-open'); });
  document.querySelectorAll('.calc-btn').forEach(btn =>
    btn.addEventListener('click', () => handleCalcInput(btn.dataset.action))
  );
  document.addEventListener('keydown', e => {
    if (!state.calcVisible || state.isLocked) return;
    const map = { '0':'0','1':'1','2':'2','3':'3','4':'4','5':'5','6':'6','7':'7','8':'8','9':'9',
                  '+':'add','-':'subtract','*':'multiply','/':'divide',
                  'Enter':'equals','=':'equals','Escape':'clear','Backspace':'clear','.':'decimal' };
    if (map[e.key]) { e.preventDefault(); handleCalcInput(map[e.key]); }
  });

  /* ── MODAL THÊM MỤC ── */
  $('modalCloseBtn').addEventListener('click', closeAddModal);
  $('modalCancelBtn').addEventListener('click', closeAddModal);
  $('modalSaveBtn').addEventListener('click', saveItem);
  $('addItemModal').addEventListener('click', e => { if (e.target === $('addItemModal')) closeAddModal(); });
  $('addItemModal').addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    if (e.target.tagName === 'TEXTAREA') return;
    /* Nếu focus đang ở nút Save, sự kiện click sẽ tự gọi saveItem — bỏ qua */
    if (e.target.id === 'modalSaveBtn' || e.target.closest('#modalSaveBtn')) return;
    e.preventDefault();
    saveItem();
  });

  /* ── FILE UPLOAD ── */
  $('fileDropZone').addEventListener('click', e => {
    if (!e.target.closest('.remove-preview-btn')) $('imageFile').click();
  });
  $('imageFile').addEventListener('change', e => { if (e.target.files[0]) handleImageFile(e.target.files[0]); });
  ['dragover','dragleave','drop'].forEach(evt =>
    $('fileDropZone').addEventListener(evt, e => {
      e.preventDefault();
      $('fileDropZone').classList.toggle('drag-over', evt === 'dragover');
      if (evt === 'drop' && e.dataTransfer.files[0]) handleImageFile(e.dataTransfer.files[0]);
    })
  );
  $('removePreviewBtn').addEventListener('click', e => {
    e.stopPropagation();
    state.imageBase64 = null; state.imageFileName = null;
    $('imageFile').value = '';
    $('imagePreviewWrap').classList.add('hidden');
    $('dropZoneContent').classList.remove('hidden');
  });

  /* ── DOCUMENT FILE UPLOAD ── */
  $('docDropZone').addEventListener('click', e => {
    if (!e.target.closest('.remove-preview-btn')) $('docFile').click();
  });
  $('docFile').addEventListener('change', e => {
    if (e.target.files[0]) handleDocumentFile(e.target.files[0]);
  });
  ['dragover','dragleave','drop'].forEach(evt =>
    $('docDropZone').addEventListener(evt, e => {
      e.preventDefault();
      $('docDropZone').classList.toggle('drag-over', evt === 'dragover');
      if (evt === 'drop' && e.dataTransfer.files[0]) handleDocumentFile(e.dataTransfer.files[0]);
    })
  );
  $('removeDocBtn').addEventListener('click', e => {
    e.stopPropagation();
    state.docBase64 = null; state.docFileName = null;
    state.docMimeType = null; state.docFileSize = 0;
    $('docFile').value = '';
    $('docSelectedWrap').classList.add('hidden');
    $('docDropContent').classList.remove('hidden');
  });

  /* ── CONFIRM MODAL ── */
  $('confirmCancelBtn').addEventListener('click', closeConfirm);
  $('confirmOkBtn').addEventListener('click', () => { state.confirmCb?.(); closeConfirm(); });
  $('confirmModal').addEventListener('click', e => { if (e.target === $('confirmModal')) closeConfirm(); });

  /* ── TRASH ── */
  $('emptyTrashBtn').addEventListener('click', emptyTrash);

  /* ── PHÍM TẮT TOÀN CỤC ── */
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    // Đóng modal thêm/sửa
    if (!$('addItemModal').classList.contains('hidden')) {
      closeAddModal();
      return;
    }
    // Đóng modal xác nhận
    if (!$('confirmModal').classList.contains('hidden')) {
      closeConfirm();
      return;
    }
    // Đóng máy tính
    if (state.calcVisible) {
      toggleCalc();
    }
  });

  /* ── TỰ ĐỘNG XÓA THÔNG BÁO LOCKOUT KHI HẾT HẠN ── */
  setInterval(() => {
    if (state.lockedUntil > 0 && Date.now() > state.lockedUntil) {
      state.lockedUntil = 0;
      const err = $('loginError');
      if (err && err.textContent.includes('Khóa')) {
        err.textContent = 'Bạn có thể thử lại ngay bây giờ.';
        setTimeout(() => err.classList.add('hidden'), 3000);
      }
    }
  }, 1000);
}

/* ============================================================
   INIT — Khởi động ứng dụng
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  initFirebase();
  initParticles();
  initLockScreen();
  setupEvents();
});
