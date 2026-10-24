// ページごとの kintone クライアント(worker-kit の createKintone を、サイトの Durable Object 経由の fetch で組む)と、
// API トークンの取り出し・フィールド定義のキャッシュ(§4.4。個人情報を含まないので 5 分)
import { createKintone } from './kit/kintone.js';
import { FORM_CACHE_MS, KINTONE_FILE_TIMEOUT_MS, KINTONE_TIMEOUT_MS } from './config.js';
import { decryptToken } from './crypto.js';
import { getFormCache, putFormCache } from './db.js';
import { GATE_HEADER, gateStub } from './gate.js';

export function kintoneFor(env, site, page) {
  const stub = gateStub(env, site.id);
  const fetchImpl = (url, init) => {
    const { kintauros, signal, ...rest } = init || {};
    const isFile = !!(kintauros && kintauros.file);
    const headers = { ...(rest.headers || {}), [GATE_HEADER]: JSON.stringify({ app: page.app_id, count: !isFile, limit: page.settings.dailyLimit, timeoutMs: isFile ? KINTONE_FILE_TIMEOUT_MS : KINTONE_TIMEOUT_MS }) };
    return stub.fetch(url, { ...rest, headers });
  };
  return createKintone({ userAgent: 'kintauros-mypage-vault', timeoutMs: KINTONE_TIMEOUT_MS + 1000, fileTimeoutMs: KINTONE_FILE_TIMEOUT_MS + 1000, fetchImpl });
}

export const pageToken = (env, page) => decryptToken(env, page.dek_wrapped, page.token_enc);
export const pageAddToken = (env, page) => decryptToken(env, page.dek_wrapped, page.add_token_enc);

// フィールド定義とレイアウト。戻り値: { ok: true, fields, layout } | { ok: false, error }
export async function formDef(env, site, page, k, token, { force = false } = {}) {
  if (!force) {
    const c = await getFormCache(env.DB, page.id);
    if (c && c.fields && c.layout && Date.now() - Date.parse(c.fetchedAt) < FORM_CACHE_MS) return { ok: true, fields: c.fields, layout: c.layout, cached: true };
  }
  const [f, l] = await Promise.all([k.getFormFields(site.domain, page.app_id, token), k.getFormLayout(site.domain, page.app_id, token)]);
  if (!f.ok) return { ok: false, error: f };
  if (!l.ok) return { ok: false, error: l };
  await putFormCache(env.DB, page.id, f.properties, l.layout);
  return { ok: true, fields: f.properties, layout: l.layout, cached: false };
}

// kintone / ゲートのエラーを画面向けの種類に分類する
export function classifyPageError(r) {
  const code = (r && r.code) || '';
  if (code === 'KINTAUROS_DAILY_LIMIT') return 'daily_limit';
  if (code === 'KINTAUROS_BUSY' || r.status === 429) return 'busy';
  if (code === 'CB_AU01' || r.status === 401 || code === 'GAIA_NO01' || code === 'GAIA_IA02') return 'token';
  if (r.status === 400) return 'query';
  if (r.status === 0 || code === 'KINTAUROS_NETWORK' || r.status >= 500) return 'unreachable';
  return 'unexpected';
}
