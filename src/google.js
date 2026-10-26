// Google でログイン(OIDC。設計 §4.2.4。mypage-worker の google.js から移したもの)。リダイレクト先は画面側の auth.kintauros.me のまま(VAULT 設計 V4)。
//   画面側はコードと state を保管庫へ渡すだけで、PKCE の verifier とクライアントシークレットは保管庫にしか無い。
//   受け付けるアドレス: @gmail.com、または email_verified かつ hd(Workspace のドメイン)がアドレスのドメインと一致するものだけ。
//   それ以外は「このアカウントではアドレスを確認できない」としてメールの確認コードに回す(照合キーがアドレスなので緩めない)
const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);

const b64url = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64url = (text) => {
  const t = String(text).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export const googleConfigured = (env) => !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);

export async function pkcePair() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return { verifier, challenge };
}

export function authorizeUrl(env, { redirectUri, state, nonce, challenge, loginHint }) {
  const p = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  });
  if (loginHint) p.set('login_hint', loginHint);
  return `${AUTH_URL}?${p}`;
}

export async function exchangeCode(env, { code, redirectUri, verifier }) {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri, grant_type: 'authorization_code', code_verifier: verifier }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.id_token) return { ok: false, error: body.error || `http_${res.status}` };
  return { ok: true, idToken: body.id_token };
}

let jwksCache = null;
async function jwks() {
  if (jwksCache && Date.now() - jwksCache.at < 60 * 60 * 1000) return jwksCache.keys;
  const res = await fetch(JWKS_URL);
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !Array.isArray(body.keys)) return [];
  jwksCache = { at: Date.now(), keys: body.keys };
  return jwksCache.keys;
}

// ID トークンの検証: 署名(RS256・Google の JWKS)・iss・aud・exp・nonce。戻り値: { ok, claims } | { ok: false, error }
export async function verifyIdToken(env, idToken, nonce, { now = Date.now(), keys } = {}) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) return { ok: false, error: 'malformed' };
  let header, claims;
  try {
    header = JSON.parse(new TextDecoder().decode(unb64url(parts[0])));
    claims = JSON.parse(new TextDecoder().decode(unb64url(parts[1])));
  } catch {
    return { ok: false, error: 'malformed' };
  }
  if (header.alg !== 'RS256') return { ok: false, error: 'alg' };
  const list = keys || (await jwks());
  const jwk = list.find((k) => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) return { ok: false, error: 'kid' };
  const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) return { ok: false, error: 'signature' };
  if (!ISSUERS.has(claims.iss)) return { ok: false, error: 'iss' };
  if (claims.aud !== env.GOOGLE_CLIENT_ID) return { ok: false, error: 'aud' };
  if (!claims.exp || claims.exp * 1000 < now - 60 * 1000) return { ok: false, error: 'exp' };
  if (!nonce || claims.nonce !== nonce) return { ok: false, error: 'nonce' };
  if (!claims.sub || typeof claims.sub !== 'string') return { ok: false, error: 'sub' };
  return { ok: true, claims };
}

// アドレスの受け付け条件(§2.4 G3)。戻り値: { accepted: true, email } | { accepted: false, email, reason }
export function acceptEmail(claims) {
  const email = String(claims.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return { accepted: false, email: '', reason: 'no_email' };
  const domain = email.split('@')[1];
  if (domain === 'gmail.com' || domain === 'googlemail.com') return { accepted: true, email };
  const hd = String(claims.hd || '').trim().toLowerCase();
  if (claims.email_verified === true && hd && domain === hd) return { accepted: true, email };
  return { accepted: false, email, reason: 'unverified' };
}
