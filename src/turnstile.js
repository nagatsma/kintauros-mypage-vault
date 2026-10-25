// Turnstile の検証(保管庫で行う。画面側がボット対策を飛ばせないように)。TURNSTILE_SECRET が未設定なら検証しない(レート制限だけ)。
//   ウィジェットはメンバーの画面(kintauros.me)に出し、受け取ったトークンを画面側がそのまま渡す。ホスト名はそのサイトのものに限る
import { hostBelongs } from './hosts.js';

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export async function turnstileOk(env, site, { token, ip }) {
  if (!env.TURNSTILE_SECRET) return true;
  if (typeof token !== 'string' || !token || token.length > 4096) return false;
  try {
    const res = await fetch(SITEVERIFY, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, ...(ip ? { remoteip: ip } : {}) }) });
    const body = await res.json().catch(() => ({}));
    if (body.success !== true) return false;
    return !body.hostname || hostBelongs(env, site, String(body.hostname).toLowerCase());
  } catch (err) {
    console.error(`[turnstile] ${err.message}`);
    return false;
  }
}
