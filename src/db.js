// D1 アクセスの薄い層。クエリは必ず .bind() のプリペアドステートメント(SERVICE-POLICY §4-6)。
// 不変条件: レコードの内容・添付・生のアドレスをこの DB に入れない
import { nowIso, safeJsonParse } from './util.js';
import { OPS_LOG_KEEP_DAYS, RATE_EVENTS_KEEP_MS } from './config.js';

const parseSite = (row) => (row ? { ...row, settings: safeJsonParse(row.settings, {}) } : null);
const parsePage = (row) => (row ? { ...row, settings: safeJsonParse(row.settings, {}) } : null);

export async function getSiteById(db, id) {
  return parseSite(await db.prepare('SELECT * FROM sites WHERE id = ?').bind(id).first());
}
export async function getSiteBySlug(db, slug) {
  return parseSite(await db.prepare('SELECT * FROM sites WHERE slug = ?').bind(slug).first());
}
export async function getSiteByDomain(db, domain) {
  return parseSite(await db.prepare('SELECT * FROM sites WHERE domain = ?').bind(domain).first());
}
export async function getSiteByCustomHost(db, host) {
  return parseSite(await db.prepare('SELECT * FROM sites WHERE custom_host = ?').bind(host).first());
}
export async function getPageById(db, id) {
  return parsePage(await db.prepare('SELECT * FROM pages WHERE id = ?').bind(id).first());
}
export async function getPageBySlug(db, siteId, slug) {
  return parsePage(await db.prepare('SELECT * FROM pages WHERE site_id = ? AND slug = ?').bind(siteId, slug).first());
}
export async function getPageByApp(db, siteId, appId) {
  return parsePage(await db.prepare('SELECT * FROM pages WHERE site_id = ? AND app_id = ?').bind(siteId, appId).first());
}
export async function listPages(db, siteId) {
  const r = await db.prepare('SELECT * FROM pages WHERE site_id = ? ORDER BY created_at').bind(siteId).all();
  return r.results.map(parsePage);
}
// サイトの設定 pageOrder(メニューの順)で並べ替える
export function orderPages(site, pages) {
  const order = Array.isArray(site.settings.pageOrder) ? site.settings.pageOrder : [];
  const idx = (p) => {
    const i = order.indexOf(p.id);
    return i < 0 ? order.length + pages.indexOf(p) : i;
  };
  return pages.slice().sort((a, b) => idx(a) - idx(b));
}

export async function updateSiteSettings(db, siteId, settings, byPageId) {
  const now = nowIso();
  await db.prepare('UPDATE sites SET settings = ?, settings_updated_by = ?, settings_updated_at = ?, updated_at = ? WHERE id = ?')
    .bind(JSON.stringify(settings), byPageId || null, now, now, siteId).run();
}
// LINE のチャネル(§4.2.10)。secretEnc はサイト DEK で暗号化済み。null で解除
export async function setSiteLine(db, siteId, { channelId, secretEnc, dekWrapped }) {
  await db.prepare('UPDATE sites SET line_channel_id = ?, line_secret_enc = ?, dek_wrapped = COALESCE(?, dek_wrapped), updated_at = ? WHERE id = ?')
    .bind(channelId || null, secretEnc || null, dekWrapped || null, nowIso(), siteId).run();
}
export async function setSiteDek(db, siteId, dekWrapped) {
  await db.prepare('UPDATE sites SET dek_wrapped = ? WHERE id = ? AND dek_wrapped IS NULL').bind(dekWrapped, siteId).run();
}
export async function updatePageSettings(db, pageId, settings) {
  await db.prepare('UPDATE pages SET settings = ?, updated_at = ? WHERE id = ?').bind(JSON.stringify(settings), nowIso(), pageId).run();
}
export async function setPageToken(db, pageId, { tokenEnc, last4 }) {
  const now = nowIso();
  await db.prepare('UPDATE pages SET token_enc = ?, token_last4 = ?, token_verified_at = ?, token_error = NULL, updated_at = ? WHERE id = ?')
    .bind(tokenEnc, last4, now, now, pageId).run();
  return now;
}
export async function clearPageToken(db, pageId, error = null) {
  await db.prepare('UPDATE pages SET token_enc = NULL, token_last4 = NULL, token_verified_at = NULL, token_error = ?, updated_at = ? WHERE id = ?')
    .bind(error, nowIso(), pageId).run();
}
// 追加専用トークン(自己登録。§19)
export async function setPageAddToken(db, pageId, { tokenEnc, last4 }) {
  const now = nowIso();
  await db.prepare('UPDATE pages SET add_token_enc = ?, add_token_last4 = ?, add_token_verified_at = ?, add_token_error = NULL, updated_at = ? WHERE id = ?').bind(tokenEnc, last4, now, now, pageId).run();
}
export async function clearPageAddToken(db, pageId, error = null) {
  await db.prepare('UPDATE pages SET add_token_enc = NULL, add_token_last4 = NULL, add_token_verified_at = NULL, add_token_error = ?, updated_at = ? WHERE id = ?').bind(error, nowIso(), pageId).run();
}
export async function markAddTokenVerified(db, pageId) {
  await db.prepare('UPDATE pages SET add_token_verified_at = ?, add_token_error = NULL WHERE id = ?').bind(nowIso(), pageId).run();
}
export async function markTokenVerified(db, pageId) {
  const now = nowIso();
  await db.prepare('UPDATE pages SET token_verified_at = ?, token_error = NULL WHERE id = ?').bind(now, pageId).run();
}

// ---- フィールド定義のキャッシュ ----
export async function getFormCache(db, pageId) {
  const row = await db.prepare('SELECT * FROM form_cache WHERE page_id = ?').bind(pageId).first();
  if (!row) return null;
  return { fields: safeJsonParse(row.fields, null), layout: safeJsonParse(row.layout, null), fetchedAt: row.fetched_at };
}
export async function putFormCache(db, pageId, fields, layout) {
  await db.prepare('INSERT INTO form_cache (page_id, fields, layout, fetched_at) VALUES (?, ?, ?, ?) ON CONFLICT(page_id) DO UPDATE SET fields = excluded.fields, layout = excluded.layout, fetched_at = excluded.fetched_at')
    .bind(pageId, JSON.stringify(fields), JSON.stringify(layout), nowIso()).run();
}

// ---- 一時コード ----
export async function insertCode(db, { id, siteId, kind, hash, data, expiresAt }) {
  await db.prepare('INSERT INTO codes (id, site_id, kind, hash, data, attempts, expires_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .bind(id, siteId, kind, hash, JSON.stringify(data), expiresAt).run();
}
export async function getCode(db, id, kind) {
  const row = await db.prepare('SELECT * FROM codes WHERE id = ? AND kind = ?').bind(id, kind).first();
  if (!row) return null;
  return { ...row, data: safeJsonParse(row.data, {}) };
}
export async function bumpCodeAttempts(db, id) {
  await db.prepare('UPDATE codes SET attempts = attempts + 1 WHERE id = ?').bind(id).run();
}
// 照合の 1 回分を確保する(原子的。並列に送られても上限を超えない)。戻り値: { attempts }(確保後の回数)| null(上限)
export async function reserveCodeAttempt(db, id, max) {
  return db.prepare('UPDATE codes SET attempts = attempts + 1 WHERE id = ? AND attempts < ? RETURNING attempts').bind(id, max).first();
}
// 取り出して消す(1 回限り。並列でも 1 つだけが受け取る)
export async function takeCode(db, id, kind) {
  const row = await db.prepare('DELETE FROM codes WHERE id = ? AND kind = ? RETURNING *').bind(id, kind).first();
  return row ? { ...row, data: safeJsonParse(row.data, {}) } : null;
}
export async function deleteCode(db, id) {
  await db.prepare('DELETE FROM codes WHERE id = ?').bind(id).run();
}

// ---- レート制限 ----
export async function countRate(db, siteId, kind, keyHash, sinceIso) {
  const row = await db.prepare('SELECT COUNT(*) AS n FROM rate_events WHERE site_id = ? AND kind = ? AND key_hash = ? AND at > ?').bind(siteId, kind, keyHash, sinceIso).first();
  return Number(row?.n || 0);
}
export async function addRate(db, siteId, kind, keyHash) {
  await db.prepare('INSERT INTO rate_events (site_id, kind, key_hash, at) VALUES (?, ?, ?, ?)').bind(siteId, kind, keyHash, nowIso()).run();
}

// ---- MAU ----
export async function touchMau(db, siteId, month, memberHash) {
  await db.prepare('INSERT OR IGNORE INTO mau (site_id, month, member_hash) VALUES (?, ?, ?)').bind(siteId, month, memberHash).run();
}
export async function mauCounts(db, siteId, months) {
  const out = {};
  for (const m of months) {
    const row = await db.prepare('SELECT COUNT(*) AS n FROM mau WHERE site_id = ? AND month = ?').bind(siteId, m).first();
    out[m] = Number(row?.n || 0);
  }
  return out;
}

export async function logOp(db, siteId, pageId, actor, action, detail) {
  await db.prepare('INSERT INTO ops_log (site_id, page_id, actor, action, detail, at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(siteId, pageId || null, actor, action, detail ? JSON.stringify(detail) : null, nowIso()).run();
}

// 日次の掃除(期限切れコード・古いレート制限・古いログ・前々月の MAU・期限の過ぎたログアウトの記録)
export async function cleanup(db) {
  const now = new Date();
  const prev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)).toISOString().slice(0, 7);
  await db.batch([
    db.prepare('DELETE FROM codes WHERE expires_at < ?').bind(now.toISOString()),
    db.prepare('DELETE FROM rate_events WHERE at < ?').bind(new Date(now.getTime() - RATE_EVENTS_KEEP_MS).toISOString()),
    db.prepare('DELETE FROM ops_log WHERE at < ?').bind(new Date(now.getTime() - OPS_LOG_KEEP_DAYS * 24 * 60 * 60 * 1000).toISOString()),
    db.prepare('DELETE FROM mau WHERE month < ?').bind(prev),
    db.prepare('DELETE FROM revoked_sessions WHERE expires_at < ?').bind(now.toISOString()),
  ]);
}

// ページの削除(トークン・キャッシュも消す)。サイトにページが無くなればサイトも消す
export async function deletePage(db, page) {
  await db.batch([
    db.prepare('DELETE FROM form_cache WHERE page_id = ?').bind(page.id),
    db.prepare('DELETE FROM pages WHERE id = ?').bind(page.id),
  ]);
  const left = await db.prepare('SELECT COUNT(*) AS n FROM pages WHERE site_id = ?').bind(page.site_id).first();
  if (Number(left?.n || 0) === 0) await deleteSite(db, page.site_id);
  return Number(left?.n || 0);
}
export async function deleteSite(db, siteId) {
  await db.batch([
    db.prepare('DELETE FROM form_cache WHERE page_id IN (SELECT id FROM pages WHERE site_id = ?)').bind(siteId),
    db.prepare('DELETE FROM pages WHERE site_id = ?').bind(siteId),
    db.prepare('DELETE FROM codes WHERE site_id = ?').bind(siteId),
    db.prepare('DELETE FROM rate_events WHERE site_id = ?').bind(siteId),
    db.prepare('DELETE FROM mau WHERE site_id = ?').bind(siteId),
    db.prepare('DELETE FROM revoked_sessions WHERE site_id = ?').bind(siteId),
    db.prepare('DELETE FROM sites WHERE id = ?').bind(siteId),
  ]);
}
