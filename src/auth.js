// ページ鍵による認証(プラグイン API)。鍵は X-Kintauros-Mypage-Key ヘッダー(kintone.plugin.app.proxy が付与、
// または設定画面が getProxyConfig で取り出して直接付与)。DB には SHA-256 のみ保存
import { getPageById } from './db.js';
import { sha256Hex, timingSafeEqual } from './util.js';

export const KEY_HEADER = 'X-Kintauros-Mypage-Key';
export const KEY_MIN_LENGTH = 32;

export function extractKey(request) {
  const h = request.headers.get(KEY_HEADER);
  if (h && h.trim()) return h.trim();
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}
export function isPlausibleKey(key) {
  return typeof key === 'string' && key.length >= KEY_MIN_LENGTH && key.length <= 256 && /^[A-Za-z0-9_-]+$/.test(key);
}
// 戻り値: page(認証成功)| null
export async function authenticatePage(request, env, pageId) {
  const key = extractKey(request);
  if (!isPlausibleKey(key)) return null;
  const page = await getPageById(env.DB, pageId);
  if (!page) return null;
  if (!timingSafeEqual(await sha256Hex(key), page.key_hash)) return null;
  return page;
}

// サイト全体に効く操作(サイト設定・一斉ログアウト・LINE)を受け付けるページか。閲覧+編集の API トークンが登録済みで
// 権限の検証に通っていること(トークンはそのドメインのアプリ管理者しか発行できないので、ドメインを持っている証明になる)。
// ページの登録は本文の domain を信じるしかないため、トークンの無いページの鍵ではサイト全体を変えさせない(VAULT 設計 §7)
export const SITE_ADMIN_ERROR = 'site_admin_requires_token';
export function isSiteAdmin(page) {
  return !!(page && page.token_enc && !page.token_error);
}
