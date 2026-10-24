// 複製元: kintauros-plugins の packages/worker-kit/src/util.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
// 共通ユーティリティ(依存なし)。publish-worker/src/util.js と同じ実装を Worker 間で共用する
export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}

export function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...headers },
  });
}

export async function readJson(request, maxBytes = 25 * 1024 * 1024) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > maxBytes) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export function nowIso() {
  return new Date().toISOString();
}

export function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

const HEX = '0123456789abcdef';
export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15];
  return s;
}

export async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

// URL セーフな乱数トークン(base64url)。鍵・Webhook シークレットに使う
export function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  let bin = '';
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// 長さの異なる入力でも一定時間で比較する
export function timingSafeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

export function safeJsonParse(text, fallback = null) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}
