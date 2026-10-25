export { json, html, readJson, nowIso, escapeHtml, sha256Hex, randomToken, timingSafeEqual, safeJsonParse, bytesToHex } from './kit/util.js';

// Cookie の読み取り(名前 → 値)
export function parseCookies(request) {
  const out = {};
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    if (k && out[k] === undefined) out[k] = part.slice(i + 1).trim();
  }
  return out;
}

// Set-Cookie の組み立て。`__Host-` プレフィックスは Secure + Path=/ + Domain なしが必須
export function cookieHeader(name, value, { maxAge, secure = true, httpOnly = true, sameSite = 'Lax', path = '/' } = {}) {
  const parts = [`${name}=${value}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  if (maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  return parts.join('; ');
}

export const redirect = (location, headers = {}) => new Response(null, { status: 302, headers: { Location: location, ...headers } });

// クライアント IP(Cloudflare が付ける)
export const clientIp = (request) => request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';

// 戻り先(next)はサイト内の絶対パスだけを許す(オープンリダイレクト防止)
export function safeNext(next) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//') || next.includes('\\') || next.length > 500) return '/';
  if (next.startsWith('/_') && !/^\/_card(\/\d{1,12})?$/.test(next)) return '/'; // /_card(メンバー証)だけは戻り先にできる
  return next;
}

export const utcDay = (d = new Date()) => d.toISOString().slice(0, 10);   // kintone の日次上限は 9:00 JST = 0:00 UTC にリセット
export const utcMonth = (d = new Date()) => d.toISOString().slice(0, 7);
