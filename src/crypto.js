// 保管庫の暗号化・署名(実装は src/kit/crypto.js)。
//   KEK: Worker シークレット VAULT_KEK(base64 の 32 バイト)。ページ DEK(API トークン)・サイト DEK(LINE のシークレット)を包む。
//        保管庫のアカウントにだけ置く(画面側の MYPAGE_KEK とは別の値。変えると保管庫の全トークンが復号できなくなる)
//   HMAC(用途ごとに鍵を分ける): 確認コード / 受け渡しコード / Cookie の署名 / state / 添付の識別子 / アドレス・IP のハッシュ
import { createEnvelope, decryptJson, encryptJson } from './kit/crypto.js';

const envelope = createEnvelope({ kekVar: 'VAULT_KEK', hmacInfo: 'kintauros-mypage/hash' });
export const kekConfigured = envelope.kekConfigured;
export const newWrappedDek = envelope.newWrappedDek;
export const unwrapDek = envelope.unwrapDek;

export const INFO = {
  hash: 'kintauros-mypage/hash',        // アドレス・IP のハッシュ(ログ・レート制限・MAU)
  code: 'kintauros-mypage/code',        // 確認コード・受け渡しコード
  session: 'kintauros-mypage/session',  // 本人確認の Cookie
  menu: 'kintauros-mypage/menu',        // メニューの Cookie
  state: 'kintauros-mypage/state',      // Google の state・PKCE の Cookie
  file: 'kintauros-mypage/file',        // 添付の署名付き識別子
  csrf: 'kintauros-mypage/csrf',        // 編集フォームごとのトークン(§4.5。サイト・メンバー・ページ・レコードに結び付ける)
  signup: 'kintauros-mypage/signup',    // 自己登録の画面のトークン(本人確認した識別子・ページ・30 分。§19)
};

export const hmacHex = (env, text, info = INFO.hash) => envelope.hmacHex(env, text, info);
export const hmacB64url = (env, text, info) => envelope.hmacB64url(env, text, info);

// アドレスは必ず小文字・前後の空白除去のうえハッシュする(照合と同じ正規化)
export const normalizeEmail = (s) => String(s || '').trim().toLowerCase();
export const emailHash = (env, email) => hmacHex(env, `email:${normalizeEmail(email)}`);
export const ipHash = (env, ip) => hmacHex(env, `ip:${ip || ''}`);

// ---- API トークン(ページ DEK で暗号化)----
export async function encryptToken(env, wrapped, token) {
  const dek = await unwrapDek(env, wrapped);
  return encryptJson(dek, { token });
}
export async function decryptToken(env, wrapped, enc) {
  if (!enc) return null;
  const dek = await unwrapDek(env, wrapped);
  const obj = await decryptJson(dek, enc);
  return obj && typeof obj.token === 'string' ? obj.token : null;
}

// ---- 署名付きの値(base64url(JSON) + '.' + HMAC)。Cookie・state・添付の識別子に使う ----
const te = new TextEncoder();
const td = new TextDecoder();
const b64urlEncode = (bytes) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const b64urlDecode = (text) => {
  const bin = atob(String(text).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
export async function sign(env, obj, info) {
  const payload = b64urlEncode(te.encode(JSON.stringify(obj)));
  const sig = await hmacB64url(env, payload, info);
  return `${payload}.${sig}`;
}
// 戻り値: obj | null(改ざん・形式違い)。期限は呼び出し側が exp で判定する
export async function verify(env, text, info) {
  if (typeof text !== 'string' || text.length > 8192) return null;
  const i = text.indexOf('.');
  if (i <= 0) return null;
  const payload = text.slice(0, i);
  const sig = text.slice(i + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(payload) || !/^[A-Za-z0-9_-]{43}$/.test(sig)) return null;
  const expected = await hmacB64url(env, payload, info);
  if (!constantEqual(expected, sig)) return null;
  try {
    return JSON.parse(td.decode(b64urlDecode(payload)));
  } catch {
    return null;
  }
}
function constantEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// 6 桁の確認コード(先頭 0 あり)
export const newEmailCode = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');

// ---- サイトの秘密(LINE のチャネルシークレット。サイト DEK で暗号化)----
export async function encryptSecret(env, wrapped, secret) {
  const dek = await unwrapDek(env, wrapped);
  return encryptJson(dek, { secret });
}
export async function decryptSecret(env, wrapped, enc) {
  if (!enc || !wrapped) return null;
  const dek = await unwrapDek(env, wrapped);
  const obj = await decryptJson(dek, enc);
  return obj && typeof obj.secret === 'string' ? obj.secret : null;
}
