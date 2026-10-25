// 複製元: kintauros-plugins の packages/worker-kit/src/crypto.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
// エンベロープ暗号化と HMAC(Web Crypto だけを使う。Workers・ブラウザ共通)。
//   - KEK: Worker シークレット(base64 の 32 バイト)。名前は Worker ごとに違う(publish: SUBMISSION_KEK / mypage: MYPAGE_KEK)ので
//     createEnvelope({ kekVar, hmacInfo }) で束ねて使う
//   - DEK: テナント(ページ)ごとの AES-256-GCM 鍵。API トークン・一時的な本文を暗号化する
//   - 管理者専用鍵: ECDH P-256 の公開鍵(JWK)で ECIES(一時鍵 + HKDF-SHA256 + AES-256-GCM)。info は呼び出し側が固定する
// 出力はすべて JSON 文字列(D1 の TEXT 列に入れる)。形式:
//   DEK 包み: { alg: 'A256GCM-KW', iv, ct } / JSON: { alg: 'A256GCM', iv, ct } / ECIES: { alg: 'ECIES-P256', epk: <JWK>, iv, ct }
import { safeJsonParse } from './util.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
};
export const unb64 = (text) => {
  const bin = atob(String(text || '').replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
export const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function aesEncrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv: b64(iv), ct: b64(ct) };
}
async function aesDecrypt(key, obj) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(obj.iv) }, key, unb64(obj.ct));
}

// ---- KEK に紐づく操作(Worker ごとにシークレット名と HMAC の用途文字列を変える)----
export function createEnvelope({ kekVar, hmacInfo }) {
  const configured = (env) => typeof env[kekVar] === 'string' && env[kekVar].length >= 32;
  let kekCache = null;
  const importKek = async (env) => {
    if (!configured(env)) throw new Error(`${kekVar} is not configured`);
    if (kekCache && kekCache.src === env[kekVar]) return kekCache.key;
    const raw = unb64(env[kekVar]);
    if (raw.length !== 32) throw new Error(`${kekVar} must be 32 bytes (base64)`);
    const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    kekCache = { src: env[kekVar], key };
    return key;
  };
  // HMAC 鍵は KEK から HKDF で派生させる(KEK 自体は使い回さない)。info ごとにキャッシュ
  const hmacCache = new Map();
  const hmacKey = async (env, info) => {
    if (!configured(env)) throw new Error(`${kekVar} is not configured`);
    const hit = hmacCache.get(info);
    if (hit && hit.src === env[kekVar]) return hit.key;
    const base = await crypto.subtle.importKey('raw', unb64(env[kekVar]), { name: 'HKDF' }, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) }, base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']);
    hmacCache.set(info, { src: env[kekVar], key });
    return key;
  };
  return {
    kekConfigured: configured,
    async newWrappedDek(env) {
      const kek = await importKek(env);
      const dek = crypto.getRandomValues(new Uint8Array(32));
      const w = await aesEncrypt(kek, dek);
      return JSON.stringify({ alg: 'A256GCM-KW', ...w });
    },
    async unwrapDek(env, wrapped) {
      const kek = await importKek(env);
      const obj = safeJsonParse(wrapped);
      if (!obj || !obj.iv || !obj.ct) throw new Error('invalid wrapped DEK');
      const raw = await aesDecrypt(kek, obj);
      return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    },
    // HMAC-SHA256 の hex。info を省略すると hmacInfo(既定の用途)
    async hmacHex(env, text, info = hmacInfo) {
      const sig = await crypto.subtle.sign('HMAC', await hmacKey(env, info), enc.encode(text));
      let s = '';
      for (const b of new Uint8Array(sig)) s += b.toString(16).padStart(2, '0');
      return s;
    },
    // HMAC-SHA256 の base64url(署名付き Cookie・state 用)
    async hmacB64url(env, text, info = hmacInfo) {
      const sig = await crypto.subtle.sign('HMAC', await hmacKey(env, info), enc.encode(text));
      return b64url(sig);
    },
  };
}

// ---- DEK で JSON を暗号化 / 復号 ----
export async function encryptJson(dekKey, obj) {
  const r = await aesEncrypt(dekKey, enc.encode(JSON.stringify(obj)));
  return JSON.stringify({ alg: 'A256GCM', ...r });
}
export async function decryptJson(dekKey, text) {
  const obj = safeJsonParse(text);
  if (!obj || !obj.iv || !obj.ct) throw new Error('invalid ciphertext');
  return JSON.parse(dec.decode(await aesDecrypt(dekKey, obj)));
}

// ---- ファイルごとの乱数鍵(AES-256-GCM)。形式: iv(12 バイト) + 暗号文 ----
export const newFileKey = () => b64(crypto.getRandomValues(new Uint8Array(32)));
async function importFileKey(keyB64, usage) {
  const raw = unb64(keyB64);
  if (raw.length !== 32) throw new Error('invalid file key');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [usage]);
}
export async function encryptBytes(keyB64, bytes) {
  const key = await importFileKey(keyB64, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}
export async function decryptBytes(keyB64, buf) {
  const key = await importFileKey(keyB64, 'decrypt');
  const all = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (all.length < 13) throw new Error('invalid ciphertext');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.subarray(0, 12) }, key, all.subarray(12)));
}

// ---- 管理者専用鍵(公開鍵)で JSON を暗号化(ECIES)。info は用途ごとに固定する(publish: 'kintauros-publish-form/v1')----
export function isValidP256PublicJwk(jwk) {
  return !!(jwk && typeof jwk === 'object' && jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string' && !jwk.d);
}
async function eciesAesKey(sharedBits, usage, info) {
  const hk = await crypto.subtle.importKey('raw', sharedBits, { name: 'HKDF' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) }, hk, { name: 'AES-GCM', length: 256 }, false, [usage]);
}
export async function eciesEncrypt(adminPubJwk, obj, info) {
  const pub = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: adminPubJwk.x, y: adminPubJwk.y }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256);
  const aes = await eciesAesKey(shared, 'encrypt', info);
  const r = await aesEncrypt(aes, enc.encode(JSON.stringify(obj)));
  const epk = await crypto.subtle.exportKey('jwk', eph.publicKey);
  return JSON.stringify({ alg: 'ECIES-P256', epk: { kty: 'EC', crv: 'P-256', x: epk.x, y: epk.y }, ...r });
}
// 秘密鍵 JWK での復号(テストとプラグイン側の参考実装。Worker の実行経路では使わない = 当社は復号できない)
export async function eciesDecrypt(privJwk, text, info) {
  const obj = safeJsonParse(text);
  if (!obj || obj.alg !== 'ECIES-P256') throw new Error('invalid ciphertext');
  const priv = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const epk = await crypto.subtle.importKey('jwk', obj.epk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: epk }, priv, 256);
  const aes = await eciesAesKey(shared, 'decrypt', info);
  return JSON.parse(dec.decode(await aesDecrypt(aes, obj)));
}
