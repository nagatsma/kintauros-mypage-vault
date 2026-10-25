// プラグイン向け管理 API(保管庫。API_HOST = api.kintauros-vault.com)。認証は X-Kintauros-Mypage-Key(ページ鍵)。
// mypage-worker の api.js から移した(VAULT 設計 §6.1 管理向け)。トークンを返す API は作らない(状態は末尾 4 文字・検証日時・エラーだけ)
//   POST   /api/pages                          ページの登録(ドメインにサイトが無ければ作る。ライセンス確認)
//   GET    /api/pages/{id}                     状態(ページ設定・トークンの状態・サイト設定・サイトのページ一覧・本日の使用回数)
//   PUT    /api/pages/{id}                     ページ設定の更新(slug を含む)
//   DELETE /api/pages/{id}                     ページの削除(トークンは即時破棄。サイトのページが無くなればサイトも削除)
//   POST   /api/pages/{id}/token               API トークンの登録(閲覧+編集だけであることを検証。§13.1 S1)
//   DELETE /api/pages/{id}/token               トークンの破棄
//   POST   /api/pages/{id}/test                照合のテスト(アドレスに当たる件数だけ返す。レコードの内容は返さない)
//   PUT    /api/pages/{id}/site                サイト全体の設定(トークン登録済みのページの鍵だけ。最後に変えたページを記録)
//   POST   /api/pages/{id}/site/logout-all     一斉ログアウト(session_epoch を進める。同上)
//   POST   /api/pages/{id}/site/line-test      LINE チャネルのテスト(同上)
//   POST   /api/pages/{id}/line-link           LINE 連携用リンクの発行(同上)
//   /site/* はトークン(閲覧+編集・検証済み)の無いページからは 403 site_admin_requires_token(index.js。設計 §7)
//   GET    /api/slug-check?slug=               サイトのサブドメインの利用可否(認証なし)
import { normalizeKintoneDomain } from './kit/domain.js';
import { isPlausibleKey, isSiteAdmin } from './auth.js';
import { MYPAGE_PLUGIN_ID, PAGE_SLUG_RE, RESERVED_PAGE_SLUGS, RESERVED_SITE_SLUGS, SLUG_RE } from './config.js';
import { INFO, decryptSecret, encryptSecret, encryptToken, hmacHex, kekConfigured, newWrappedDek } from './crypto.js';
import { clearPageAddToken, clearPageToken, deletePage, getFormCache, getPageByApp, getPageBySlug, getSiteByDomain, getSiteBySlug, insertCode, listPages, logOp, mauCounts, orderPages, setPageAddToken, setPageToken, setSiteDek, setSiteLine, updatePageSettings, updateSiteSettings } from './db.js';
import { invalidRecordBody } from './kit/kintone.js';
import { isChannelId, isChannelSecret, lineCallbackUrl, testChannel } from './line.js';
import { qrSvg } from './qr.js';
import { gateUsage } from './gate.js';
import { formDef, kintoneFor, pageToken } from './kintone.js';
import { checkMypageLicense, refreshLicenseIfStale } from './license.js';
import { isEmail, membershipQuery, sanitizeCondition } from './match.js';
import { validatePageSettings, validateSiteSettings, cardForPage } from './settings.js';
import { json, nowIso, randomToken, readJson, sha256Hex, utcMonth } from './util.js';

export const siteUrlOf = (env, site) => (site.custom_host && site.host_status === 'active' ? `https://${site.custom_host}/` : `https://${site.slug}.${env.PUBLIC_BASE_DOMAIN}/`);
export const pageUrlOf = (env, site, page) => `${siteUrlOf(env, site)}${page.slug}/`;
export const apiBaseOf = (env) => `https://${env.API_HOST}/api/`;

export const normalizeSiteSlug = (s) => {
  const v = String(s || '').trim().toLowerCase();
  return SLUG_RE.test(v) && !RESERVED_SITE_SLUGS.has(v) ? v : null;
};
export const normalizePageSlug = (s) => {
  const v = String(s || '').trim().toLowerCase();
  return PAGE_SLUG_RE.test(v) && !RESERVED_PAGE_SLUGS.has(v) ? v : null;
};

// LINE 連携 ID に使えるフィールドの候補(文字列 1 行。メンバーのメールアドレスがテーブルの列ならその表の列)。フィールド定義のキャッシュから(無ければ空)
async function lineCandidates(env, page) {
  const c = await getFormCache(env.DB, page.id).catch(() => null);
  if (!c || !c.fields) return [];
  const m = page.settings.member || {};
  const src = m.table && c.fields[m.table] && c.fields[m.table].type === 'SUBTABLE' ? c.fields[m.table].fields || {} : c.fields;
  return Object.values(src).filter((d) => d && d.type === 'SINGLE_LINE_TEXT' && d.code !== (m.table ? m.field : m.field)).map((d) => ({ code: d.code, label: d.label || d.code })).sort((a, b) => a.label.localeCompare(b.label, 'ja'));
}

// メンバー証の QR / あわせて表示に使えるフィールドの候補(そのページで閲覧を付けたフィールド。ラベルはフィールド定義のキャッシュから)
async function cardCandidates(env, page) {
  const c = await getFormCache(env.DB, page.id).catch(() => null);
  const defs = (c && c.fields) || {};
  return Object.entries(page.settings.fields || {}).filter(([, a]) => a && a.view).map(([code]) => ({ code, label: (defs[code] && defs[code].label) || code })).sort((a, b) => a.label.localeCompare(b.label, 'ja'));
}

async function state(env, page, site, cors, extra = {}) {
  const pages = orderPages(site, await listPages(env.DB, site.id));
  const candidates = await Promise.all(pages.map((p) => lineCandidates(env, p)));
  const cardCands = await Promise.all(pages.map((p) => cardCandidates(env, p)));
  let usage = { day: null, usage: {} };
  try {
    usage = await gateUsage(env, site.id, pages.map((p) => p.app_id));
  } catch (e) {
    console.error(`[usage] ${e.message}`);
  }
  const now = new Date();
  const prev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const mau = await mauCounts(env.DB, site.id, [utcMonth(now), utcMonth(prev)]);
  const updatedBy = site.settings_updated_by ? pages.find((p) => p.id === site.settings_updated_by) : null;
  return json(
    {
      ok: true,
      apiBase: apiBaseOf(env),
      page: {
        id: page.id,
        appId: page.app_id,
        slug: page.slug,
        url: pageUrlOf(env, site, page),
        status: page.status,
        settings: page.settings,
        token: { set: !!page.token_enc, last4: page.token_last4 || null, verifiedAt: page.token_verified_at || null, error: page.token_error || null },
        addToken: { set: !!page.add_token_enc, last4: page.add_token_last4 || null, verifiedAt: page.add_token_verified_at || null, error: page.add_token_error || null },
        usageToday: usage.usage[page.app_id] ?? 0,
        siteAdmin: isSiteAdmin(page), // ドメイン全体の設定を変えられるか(トークン登録済み)
      },
      site: {
        id: site.id,
        slug: site.slug,
        domain: site.domain,
        url: siteUrlOf(env, site),
        publicBaseDomain: env.PUBLIC_BASE_DOMAIN,
        status: site.status,
        settings: site.settings,
        license: { status: site.license_status, plan: site.license_plan, expiresAt: site.license_expires_at },
        // LINE(§4.2.10)。シークレットは返さない(設定済みかどうかだけ)
        line: { channelId: site.line_channel_id || '', secretSet: !!site.line_secret_enc, callbackUrl: lineCallbackUrl(env) },
        settingsUpdatedAt: site.settings_updated_at || null,
        settingsUpdatedBy: updatedBy ? { pageId: updatedBy.id, appId: updatedBy.app_id, name: updatedBy.settings.name } : null,
        pages: pages.map((p, i) => ({ id: p.id, appId: p.app_id, slug: p.slug, name: p.settings.name, enabled: !!p.settings.enabled, tokenSet: !!p.token_enc, tokenError: p.token_error || null, url: pageUrlOf(env, site, p), usageToday: usage.usage[p.app_id] ?? 0, dailyLimit: p.settings.dailyLimit, lineField: (p.settings.line && p.settings.line.field) || '', lineCandidates: candidates[i], cardCandidates: cardCands[i], memberTable: (p.settings.member && p.settings.member.table) || '' })),
        usageDay: usage.day,
        mau,
      },
      ...extra,
    },
    200,
    cors
  );
}

// POST /api/pages  body: { domain, appId, key, name, pageSlug? }
// 本文の domain は Worker では確かめられないため、サイトを作るときもサイト全体の設定(名前・URL)は受け取らない。
// サイトの URL はドメインから決め、名前などはトークンを登録してからドメイン全体の設定で変える(設計 §7)
export async function postCreatePage(request, env, cors) {
  if (!kekConfigured(env)) return json({ ok: false, error: 'kek_not_configured' }, 503, cors);
  const body = await readJson(request, 64 * 1024);
  if (!body) return json({ ok: false, error: 'invalid_body' }, 400, cors);
  const domain = normalizeKintoneDomain(body.domain);
  if (!domain) return json({ ok: false, error: 'invalid_domain' }, 400, cors);
  const appId = String(body.appId ?? '');
  if (!/^\d{1,12}$/.test(appId)) return json({ ok: false, error: 'invalid_app_id' }, 400, cors);
  if (!isPlausibleKey(body.key)) return json({ ok: false, error: 'invalid_key' }, 400, cors);
  const name = String(body.name || '').trim().slice(0, 60) || `App ${appId}`;

  let site = await getSiteByDomain(env.DB, domain);
  if (site) {
    const dup = await getPageByApp(env.DB, site.id, appId);
    if (dup) return json({ ok: false, error: 'already_registered', pageId: dup.id, siteSlug: site.slug, pageSlug: dup.slug }, 409, cors);
  }
  // ライセンスの確認(到達不可は登録を拒否 — 表示は「許可されたときだけ」)
  const lic = await checkMypageLicense(env, domain);
  if (lic.ok !== true) return json({ ok: false, error: lic.ok === null ? 'license_unavailable' : 'license_required', license: lic }, lic.ok === null ? 503 : 403, cors);

  const now = nowIso();
  if (!site) {
    let slug = null;
    const base = domain.split('.')[0];
    const cands = [base, `${base}-${randomToken(3).toLowerCase().replace(/[^a-z0-9]/g, 'x').slice(0, 4)}`, `${base}-${randomToken(6).toLowerCase().replace(/[^a-z0-9]/g, 'x').slice(0, 6)}`];
    for (const c of cands) {
      const n = normalizeSiteSlug(c);
      if (n && !(await getSiteBySlug(env.DB, n))) { slug = n; break; }
    }
    if (!slug) return json({ ok: false, error: 'slug_generation_failed' }, 500, cors);
    const siteSettings = validateSiteSettings({ name: '' }).value;
    site = { id: crypto.randomUUID(), slug, domain, settings: siteSettings, session_epoch: 1, status: 'active', license_status: lic.status, license_plan: lic.plan, license_expires_at: lic.expiresAt };
    await env.DB
      .prepare('INSERT INTO sites (id, slug, domain, settings, session_epoch, status, license_status, license_plan, license_expires_at, license_checked_at, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)')
      .bind(site.id, slug, domain, JSON.stringify(siteSettings), 'active', lic.status, lic.plan, lic.expiresAt, now, now, now)
      .run();
    await logOp(env.DB, site.id, null, 'plugin', 'site_create', { domain, slug });
  } else {
    await env.DB.prepare('UPDATE sites SET license_status = ?, license_plan = ?, license_expires_at = ?, license_checked_at = ? WHERE id = ?').bind(lic.status, lic.plan, lic.expiresAt, now, site.id).run();
  }

  let pageSlug = body.pageSlug ? normalizePageSlug(body.pageSlug) : null;
  if (body.pageSlug && !pageSlug) return json({ ok: false, error: 'invalid_page_slug' }, 400, cors);
  if (!pageSlug) pageSlug = `app${appId}`;
  if (await getPageBySlug(env.DB, site.id, pageSlug)) return json({ ok: false, error: 'page_slug_taken' }, 409, cors);
  const settings = validatePageSettings({ name, enabled: false }).value;
  const page = { id: crypto.randomUUID(), site_id: site.id, app_id: appId, slug: pageSlug, settings, dek_wrapped: await newWrappedDek(env), status: 'active', token_enc: null };
  await env.DB
    .prepare('INSERT INTO pages (id, site_id, app_id, slug, key_hash, settings, dek_wrapped, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(page.id, site.id, appId, pageSlug, await sha256Hex(body.key), JSON.stringify(settings), page.dek_wrapped, 'active', now, now)
    .run();
  await logOp(env.DB, site.id, page.id, 'plugin', 'page_create', { appId, slug: pageSlug });
  return state(env, page, site, cors);
}

export async function getPageState(env, page, site, cors) {
  return state(env, page, site, cors);
}

// PUT /api/pages/{id}  body: { settings, slug? }
export async function putPage(request, env, page, site, cors) {
  const body = await readJson(request, 512 * 1024);
  if (!body) return json({ ok: false, error: 'invalid_body' }, 400, cors);
  if (body.slug !== undefined && body.slug !== page.slug) {
    const slug = normalizePageSlug(body.slug);
    if (!slug) return json({ ok: false, error: 'invalid_page_slug' }, 400, cors);
    if (await getPageBySlug(env.DB, site.id, slug)) return json({ ok: false, error: 'page_slug_taken' }, 409, cors);
    await env.DB.prepare('UPDATE pages SET slug = ?, updated_at = ? WHERE id = ?').bind(slug, nowIso(), page.id).run();
    page.slug = slug;
  }
  if (body.settings !== undefined) {
    const v = validatePageSettings(body.settings);
    if (!v.ok) return json({ ok: false, error: 'invalid_settings', details: v.errors }, 400, cors);
    // あわせて確認するページは同じサイトのページだけ
    const ids = new Set((await listPages(env.DB, site.id)).map((p) => p.id));
    v.value.checkPages = v.value.checkPages.filter((id) => ids.has(id) && id !== page.id);
    if (v.value.enabled && !page.token_enc) return json({ ok: false, error: 'token_required' }, 409, cors);
    // LINE 連携 ID のフィールドはドメイン全体の設定(putSite の linePageFields)で決める。ここでは既存の値を保つ
    v.value.line = { field: (page.settings.line && page.settings.line.field) || '' };
    await updatePageSettings(env.DB, page.id, v.value);
    // 「マイページを使う」をオフにして保存したら API トークンを破棄する(同意文のとおり。再開するには登録し直す)
    if (!v.value.enabled && page.add_token_enc) {
      await clearPageAddToken(env.DB, page.id);
      page.add_token_enc = null;
      page.add_token_last4 = null;
    }
    if (!v.value.enabled && page.token_enc) {
      await clearPageToken(env.DB, page.id);
      page.token_enc = null;
      page.token_last4 = null;
      page.token_verified_at = null;
      await logOp(env.DB, site.id, page.id, 'plugin', 'token_cleared', { reason: 'disabled' });
    }
    page.settings = v.value;
    await logOp(env.DB, site.id, page.id, 'plugin', 'page_update', { enabled: v.value.enabled, fields: Object.keys(v.value.fields).length, tables: Object.keys(v.value.tables).length });
  }
  return state(env, page, site, cors);
}

export async function deletePageApi(env, page, site, cors) {
  const left = await deletePage(env.DB, page);
  await logOp(env.DB, site.id, page.id, 'plugin', 'page_delete', { pagesLeft: left });
  return json({ ok: true, deleted: true, siteDeleted: left === 0 }, 200, cors);
}

// POST /api/pages/{id}/token  body: { token }
export async function postToken(request, env, page, site, cors) {
  if (!kekConfigured(env)) return json({ ok: false, error: 'kek_not_configured' }, 503, cors);
  const body = await readJson(request, 64 * 1024);
  const token = body && typeof body.token === 'string' ? body.token.trim() : '';
  if (!/^[A-Za-z0-9]{20,64}$/.test(token)) return json({ ok: false, error: 'invalid_token' }, 400, cors);
  const k = kintoneFor(env, site, page);
  const check = await k.checkViewEditOnly(site.domain, page.app_id, token);
  await logOp(env.DB, site.id, page.id, 'plugin', 'token_check', { ok: check.ok, error: check.error || null });
  if (!check.ok) return json({ ok: false, error: check.error, detail: check.detail || null }, check.error === 'unreachable' ? 503 : 400, cors);
  const enc = await encryptToken(env, page.dek_wrapped, token);
  await setPageToken(env.DB, page.id, { tokenEnc: enc, last4: token.slice(-4) });
  page.token_enc = enc;
  page.token_last4 = token.slice(-4);
  page.token_verified_at = nowIso();
  page.token_error = null;
  await formDef(env, site, page, k, token, { force: true }).catch(() => null); // フィールド定義を温める(失敗しても登録は成功)
  return state(env, page, site, cors);
}

// POST /api/pages/{id}/add-token  body: { token }  自己登録用の追加専用トークン(§19)。閲覧トークンの登録が先(検証用の本文をフィールド定義から作るため)
export async function postAddToken(request, env, page, site, cors) {
  if (!kekConfigured(env)) return json({ ok: false, error: 'kek_not_configured' }, 503, cors);
  const body = await readJson(request, 64 * 1024);
  const token = body && typeof body.token === 'string' ? body.token.trim() : '';
  if (!/^[A-Za-z0-9]{20,64}$/.test(token)) return json({ ok: false, error: 'invalid_token' }, 400, cors);
  const viewToken = await pageToken(env, page);
  if (!viewToken) return json({ ok: false, error: 'token_required' }, 409, cors);
  const k = kintoneFor(env, site, page);
  const def = await formDef(env, site, page, k, viewToken);
  if (!def.ok) return json({ ok: false, error: 'unreachable' }, 503, cors);
  const check = await k.checkAddOnly(site.domain, page.app_id, token, invalidRecordBody(def.fields));
  await logOp(env.DB, site.id, page.id, 'plugin', 'add_token_check', { ok: check.ok, error: check.error || null });
  if (!check.ok) return json({ ok: false, error: check.error, detail: check.detail || null }, check.error === 'unreachable' ? 503 : 400, cors);
  const enc = await encryptToken(env, page.dek_wrapped, token);
  await setPageAddToken(env.DB, page.id, { tokenEnc: enc, last4: token.slice(-4) });
  page.add_token_enc = enc;
  page.add_token_last4 = token.slice(-4);
  page.add_token_verified_at = nowIso();
  page.add_token_error = null;
  return state(env, page, site, cors);
}
export async function deleteAddToken(env, page, site, cors) {
  await clearPageAddToken(env.DB, page.id);
  page.add_token_enc = null;
  page.add_token_last4 = null;
  page.add_token_verified_at = null;
  await logOp(env.DB, site.id, page.id, 'plugin', 'add_token_cleared', null);
  return state(env, page, site, cors);
}

export async function deleteToken(env, page, site, cors) {
  await clearPageToken(env.DB, page.id);
  if (page.settings.enabled) {
    page.settings.enabled = false;
    await updatePageSettings(env.DB, page.id, page.settings);
  }
  page.token_enc = null;
  page.token_last4 = null;
  page.token_verified_at = null;
  await logOp(env.DB, site.id, page.id, 'plugin', 'token_cleared', null);
  return state(env, page, site, cors);
}

// POST /api/pages/{id}/test  body: { email, member?, condition? }(保存前の値でも試せる)。件数だけ返す
export async function postTest(request, env, page, site, cors) {
  const body = await readJson(request, 64 * 1024);
  const email = body && typeof body.email === 'string' ? body.email.trim() : '';
  if (!isEmail(email)) return json({ ok: false, error: 'invalid_email' }, 400, cors);
  const token = await pageToken(env, page);
  if (!token) return json({ ok: false, error: 'no_token' }, 409, cors);
  const member = body.member && typeof body.member === 'object' && body.member.field ? { field: String(body.member.field), table: String(body.member.table || '') } : page.settings.member;
  if (!member.field) return json({ ok: false, error: 'no_member_field' }, 400, cors);
  const condition = body.condition !== undefined ? sanitizeCondition(String(body.condition)) : page.settings.condition;
  const probe = { ...page, settings: { ...page.settings, member, condition } };
  const q = membershipQuery(probe, email).replace(/ limit 1$/, ' limit 100');
  const k = kintoneFor(env, site, page);
  const r = await k.getRecords(site.domain, page.app_id, token, { query: q, fields: [member.table || member.field], totalCount: true });
  if (!r.ok) return json({ ok: false, error: 'kintone_error', status: r.status, code: r.code, message: r.message }, 502, cors);
  const { filterMatches } = await import('./match.js');
  const matched = filterMatches(r.records, member, email).length;
  return json({ ok: true, count: matched, rawCount: r.totalCount ?? r.records.length }, 200, cors);
}

// PUT /api/pages/{id}/site  body: { settings?, slug?, line?: { channelId, channelSecret?, clear? } }
export async function putSite(request, env, page, site, cors) {
  const body = await readJson(request, 256 * 1024);
  if (!body) return json({ ok: false, error: 'invalid_body' }, 400, cors);
  if (body.line !== undefined) {
    const l = body.line && typeof body.line === 'object' ? body.line : {};
    if (l.clear === true) {
      await setSiteLine(env.DB, site.id, { channelId: null, secretEnc: null });
      site.line_channel_id = null;
      site.line_secret_enc = null;
      await logOp(env.DB, site.id, page.id, 'plugin', 'line_clear', null);
    } else {
      const channelId = l.channelId !== undefined ? String(l.channelId || '').trim() : site.line_channel_id || '';
      if (!isChannelId(channelId)) return json({ ok: false, error: 'invalid_line_channel_id' }, 400, cors);
      let secretEnc = site.line_secret_enc || null;
      let dekWrapped = null;
      if (l.channelSecret !== undefined && l.channelSecret !== '') {
        const secret = String(l.channelSecret).trim();
        if (!isChannelSecret(secret)) return json({ ok: false, error: 'invalid_line_channel_secret' }, 400, cors);
        if (!kekConfigured(env)) return json({ ok: false, error: 'kek_not_configured' }, 503, cors);
        if (!site.dek_wrapped) {
          dekWrapped = await newWrappedDek(env);
          await setSiteDek(env.DB, site.id, dekWrapped);
          site.dek_wrapped = dekWrapped;
        }
        secretEnc = await encryptSecret(env, site.dek_wrapped, secret);
      }
      await setSiteLine(env.DB, site.id, { channelId, secretEnc, dekWrapped });
      site.line_channel_id = channelId;
      site.line_secret_enc = secretEnc;
      await logOp(env.DB, site.id, page.id, 'plugin', 'line_set', { secret: l.channelSecret !== undefined && l.channelSecret !== '' });
    }
  }
  if (body.slug !== undefined && body.slug !== site.slug) {
    const slug = normalizeSiteSlug(body.slug);
    if (!slug) return json({ ok: false, error: 'invalid_site_slug' }, 400, cors);
    if (await getSiteBySlug(env.DB, slug)) return json({ ok: false, error: 'site_slug_taken' }, 409, cors);
    await env.DB.prepare('UPDATE sites SET slug = ?, updated_at = ? WHERE id = ?').bind(slug, nowIso(), site.id).run();
    site.slug = slug;
    await logOp(env.DB, site.id, page.id, 'plugin', 'site_slug', { slug });
  }
  if (body.linePageFields && typeof body.linePageFields === 'object') {
    for (const p of await listPages(env.DB, site.id)) {
      if (!(p.id in body.linePageFields)) continue;
      const field = typeof body.linePageFields[p.id] === 'string' ? body.linePageFields[p.id].trim() : '';
      const next = validatePageSettings({ ...p.settings, line: { field } }).value;
      if (next.line.field === ((p.settings.line && p.settings.line.field) || '')) continue;
      await updatePageSettings(env.DB, p.id, next);
      if (p.id === page.id) page.settings = next;
    }
  }
  if (body.settings !== undefined) {
    const v = validateSiteSettings(body.settings);
    if (!v.ok) return json({ ok: false, error: 'invalid_settings', details: v.errors }, 400, cors);
    const allPages = await listPages(env.DB, site.id);
    const ids = new Set(allPages.map((p) => p.id));
    v.value.topCheckPages = v.value.topCheckPages.filter((id) => ids.has(id));
    v.value.pageOrder = v.value.pageOrder.filter((id) => ids.has(id));
    // メンバー証(§18): 対象のページはこのサイトのもの。有効にするなら QR のフィールドはそのページで閲覧できるものでなければならない
    const cardPage = allPages.find((p) => p.id === v.value.card.page) || null;
    if (!cardPage) v.value.card.page = '';
    const resolved = cardForPage(v.value.card, cardPage);
    if (v.value.card.enabled && !resolved) return json({ ok: false, error: 'invalid_settings', details: [{ path: 'card.field', message: 'メンバー証の対象のアプリと、そのアプリで「閲覧」を付けた QR コードのフィールドを選んでください' }] }, 400, cors);
    if (resolved) v.value.card.fields = resolved.fields;
    await updateSiteSettings(env.DB, site.id, v.value, page.id);
    site.settings = v.value;
    site.settings_updated_by = page.id;
    site.settings_updated_at = nowIso();
    await logOp(env.DB, site.id, page.id, 'plugin', 'site_update', { login: v.value.login, sessionDays: v.value.sessionDays });
  }
  return state(env, page, site, cors);
}

// POST /api/pages/{id}/site/line-test  body: { channelId?, channelSecret? }(未指定なら保存済みの値で試す)
export async function postLineTest(request, env, page, site, cors) {
  const body = (await readJson(request, 64 * 1024)) || {};
  const channelId = body.channelId ? String(body.channelId).trim() : site.line_channel_id || '';
  let secret = body.channelSecret ? String(body.channelSecret).trim() : '';
  if (!secret && site.line_secret_enc) secret = (await decryptSecret(env, site.dek_wrapped, site.line_secret_enc).catch(() => null)) || '';
  if (!isChannelId(channelId) || !isChannelSecret(secret)) return json({ ok: false, error: 'line_not_configured' }, 400, cors);
  const r = await testChannel({ channelId, channelSecret: secret, redirectUri: lineCallbackUrl(env) });
  await logOp(env.DB, site.id, page.id, 'plugin', 'line_test', { ok: r.ok, error: r.error || null });
  if (!r.ok) return json({ ok: false, error: r.error === 'invalid_client' ? 'line_invalid_client' : r.error, detail: r.detail || null }, r.error === 'unreachable' ? 503 : 400, cors);
  return json({ ok: true }, 200, cors);
}

// POST /api/pages/{id}/line-link  body: { recordId, rowId? }  連携用リンクの発行(§4.2.10。1 回限り・既定 7 日)。レコードの内容は受け取らない
export async function postLineLink(request, env, page, site, cors) {
  const body = (await readJson(request, 64 * 1024)) || {};
  const recordId = String(body.recordId ?? '');
  const rowId = body.rowId ? String(body.rowId) : null;
  if (!/^\d{1,12}$/.test(recordId) || (rowId && !/^\d{1,12}$/.test(rowId))) return json({ ok: false, error: 'invalid_body' }, 400, cors);
  if (!(site.settings.line && site.settings.line.enabled && site.line_channel_id && site.line_secret_enc)) return json({ ok: false, error: 'line_not_configured' }, 409, cors);
  if (!page.settings.line || !page.settings.line.field) return json({ ok: false, error: 'line_field_required' }, 409, cors);
  if (!page.settings.enabled || !isSiteAdmin(page)) return json({ ok: false, error: 'page_disabled' }, 409, cors);
  if (page.settings.member.table && !rowId) return json({ ok: false, error: 'row_required' }, 400, cors);
  const code = randomToken(24);
  const id = randomToken(12);
  const days = site.settings.line.linkDays || 7;
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  await insertCode(env.DB, { id, siteId: site.id, kind: 'line_link', hash: await hmacHex(env, code, INFO.code), data: { p: page.id, r: recordId, row: rowId }, expiresAt });
  await logOp(env.DB, site.id, page.id, 'plugin', 'line_link_issue', { row: !!rowId });
  const url = `${siteUrlOf(env, site)}_line/link?c=${id}.${code}`;
  return json({ ok: true, url, expiresAt, qr: qrSvg(url) }, 200, cors);
}

export async function postLogoutAll(env, page, site, cors) {
  await env.DB.prepare('UPDATE sites SET session_epoch = session_epoch + 1, updated_at = ? WHERE id = ?').bind(nowIso(), site.id).run();
  site.session_epoch += 1;
  await logOp(env.DB, site.id, page.id, 'plugin', 'logout_all', null);
  return state(env, page, site, cors);
}

export async function getSlugCheck(url, env, cors) {
  const raw = url.searchParams.get('slug') || '';
  const slug = normalizeSiteSlug(raw);
  if (!slug) return json({ ok: true, available: false, reason: 'invalid' }, 200, cors);
  const taken = await getSiteBySlug(env.DB, slug);
  return json({ ok: true, available: !taken, reason: taken ? 'taken' : null }, 200, cors);
}

export { refreshLicenseIfStale, MYPAGE_PLUGIN_ID };
