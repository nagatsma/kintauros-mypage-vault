// メンバーのデータ(VAULT 設計 §6.1・§6.2。P3。mypage-worker の member.js・member-edit.js・login.js の kintone 呼び出しを移したもの)。
// 画面側(mypage-worker)は乗っ取られている前提で信頼しない。権限の根拠はセッション(session.js が検証済みのもの)と、ここで行う照合だけ:
//   1. 照合の条件は保管庫が組み立てる(match.js): 照合に使うフィールド = セッションの本人 + 契約者の「対象にする条件」+ エスケープした検索語。
//      取得後に保管庫で完全一致を再照合する。レコード番号だけでは開けない・書けない(画面側の申告するレコード番号は、本人の条件で取り直す)
//   2. 返すのは閲覧を許したフィールド・列・行だけ(kintone への fields 指定 settings.requestedFields と、応答の削り込み view.js の両方)。
//      フィールド定義・レイアウトも閲覧を許したものだけに絞る
//   3. 編集は入力値だけを受け取り、edit.js で検証して PUT の本文を保管庫が組み立てる(組み立て済みの本文は受け付けない)。
//      照合に使うフィールドは書き換えさせない。テーブルの行の権限(行の作成者)も保管庫で確かめる(V5)。コメントも保管庫が書く
//   4. 添付は保管庫が署名した識別子だけ(表示中のレコードの fileKey をセッション・ページ・レコードに結び付ける)。アップロードも中継だけで保存しない
//   5. 量の上限(quota.js): メンバーごとの 1 分の回数(v1.js)・1 セッションが 1 時間に取得するレコード数(ここ)
// 応答にトークン・fileKey・シークレットを含めない。D1・ログにレコードの内容・アドレスを置かない
import { CSRF_TTL_MS, FILE_LINK_TTL_MS, LAST_LOGIN_MAX_RECORDS, LIST_PAGE_SIZE, PAGE_SLUG_RE, SAVE_OPS_MAX, SEARCH_KEYWORD_MAX, TEXT_INPUT_MAX, UPLOAD_HANDLE_TTL_MS } from './config.js';
import { INFO, hmacHex, sign, verify } from './crypto.js';
import { deleteCode, getCode, getPageById, getPageBySlug, listPages, logOp, takeCode } from './db.js';
import { commentText, editableColumns, editableFieldCodes, msgFor, planFieldEdit, planSignup, planTableOps, signupFieldCodes, summarizeRow } from './edit.js';
import { FILE_MAX_BYTES, fileAllowedBy, allowedExtensionsOf } from './kit/files.js';
import { asIdent, identHash, identValue, isLine } from './ident.js';
import { classifyPageError, formDef, kintoneFor, pageAddToken, pageToken } from './kintone.js';
import { identMatches, listQuery, matchSpec, membershipQuery, normalizeEmail, pageAcceptsIdent, recordQuery } from './match.js';
import { STATE_RE, afterVerify, checkMembership, completeLogin, entryPageOf, lineConfigured, scopePages, signupCapable, usablePage } from './member-auth.js';
import { reserveRecords } from './quota.js';
import { verifySession, verifySignup } from './session.js';
import { cardForPage, requestedFields } from './settings.js';
import { sha256Hex, timingSafeEqual } from './util.js';
import { LISTABLE_TYPES, listRow, viewRecord } from './view.js';

const out = (status, body) => ({ status, body });
const fail = (status, error, extra = {}) => out(status, { ok: false, error, ...extra });
const ARRAY_MAX = 200; // 1 つの入力(複数選択・添付の識別子)の値の数
const HANDLE_RE = /^[A-Za-z0-9_-]{20,6000}\.[A-Za-z0-9_-]{43}$/;
const nowMs = () => Date.now();

// ---- 共通: ページを開く(使えるページ・本人の識別子で入れるページ・フィールド定義)----
async function openPage(env, site, slug, ident) {
  const page = PAGE_SLUG_RE.test(String(slug || '')) ? await getPageBySlug(env.DB, site.id, slug) : null;
  if (!page) return { error: fail(404, 'page_not_found') };
  if (!usablePage(page)) return { error: fail(404, 'page_stopped') };
  if (!pageAcceptsIdent(page, ident)) return { error: fail(403, 'line_not_accepted') };
  const token = await pageToken(env, page).catch(() => null);
  if (!token) return { error: fail(503, 'token') };
  const k = kintoneFor(env, site, page);
  const def = await formDef(env, site, page, k, token);
  if (!def.ok) return { error: fail(503, classifyPageError(def.error)) };
  return { page, token, k, fields: def.fields, layout: def.layout };
}

// 1 件を本人の条件で取り直す(画面側の申告するレコード番号だけでは開けない)。戻り値: { record } | { error }
async function loadRecord(env, site, o, ident, recordId) {
  if (!/^\d{1,12}$/.test(String(recordId))) return { error: fail(404, 'record_not_found') };
  const r = await o.k.getRecords(site.domain, o.page.app_id, o.token, { query: recordQuery(o.page, ident, recordId), fields: requestedFields(o.page, site) });
  if (!r.ok) return { error: fail(503, classifyPageError(r)) };
  const hit = identMatches(r.records, o.page, ident).filter((x) => String(x.$id && x.$id.value) === String(recordId));
  return hit.length ? { record: hit[0] } : { error: fail(404, 'record_not_found') };
}

// ---- 画面の組み立て用に返すもの(閲覧を許したものだけ)----
export const pageInfo = (page) => ({ slug: page.slug, name: page.settings.name || '', list: { fields: page.settings.list.fields, search: page.settings.list.search }, attachments: { extensions: allowedExtensionsOf(page.settings.attachments), maxBytes: FILE_MAX_BYTES } });

// フィールド定義: 閲覧を許したフィールド・テーブル(列は閲覧を許したものだけ)と、それらを含むグループ。ルックアップの参照先などは返さない
const DEF_KEYS = ['type', 'code', 'label', 'noLabel', 'required', 'options', 'maxLength', 'minLength', 'maxValue', 'minValue', 'protocol', 'unit', 'unitPosition', 'digit', 'displayScale', 'format', 'align', 'defaultValue', 'thumbnailSize', 'openGroup'];
const pickDef = (d) => {
  const o = {};
  for (const k of DEF_KEYS) if (d[k] !== undefined) o[k] = d[k];
  if (d.lookup) o.lookup = true;
  return o;
};
function visibleCodes(page, fields) {
  const s = page.settings;
  const top = new Set(Object.keys(s.fields).filter((c) => s.fields[c].view && fields[c] && fields[c].type !== 'SUBTABLE'));
  const tables = new Map();
  for (const [c, t] of Object.entries(s.tables)) {
    if (!fields[c] || fields[c].type !== 'SUBTABLE' || !(t.all.view || t.owner.view)) continue;
    tables.set(c, new Set(Object.keys(t.columns).filter((cc) => t.columns[cc].view && fields[c].fields && fields[c].fields[cc])));
  }
  return { top, tables };
}
export function publicLayout(page, fields, layout) {
  const { top, tables } = visibleCodes(page, fields);
  const groups = new Set();
  const walk = (rows) => (rows || []).map((row) => {
    if (row.type === 'GROUP') {
      const inner = walk(row.layout);
      if (!inner.some((r) => r.type !== 'ROW' || r.fields.some((f) => f.code))) return null;
      groups.add(row.code);
      return { type: 'GROUP', code: row.code, layout: inner };
    }
    if (row.type === 'SUBTABLE') {
      const cols = tables.get(row.code);
      return cols ? { type: 'SUBTABLE', code: row.code, fields: (row.fields || []).filter((f) => cols.has(f.code)).map((f) => ({ type: f.type, code: f.code, size: f.size })) } : null;
    }
    const fs = (row.fields || []).filter((f) => (f.code ? top.has(f.code) : ['LABEL', 'SPACER', 'HR'].includes(f.type))).map((f) => (f.code ? { type: f.type, code: f.code, size: f.size } : { type: f.type, label: f.label, elementId: f.elementId, size: f.size }));
    return fs.length ? { type: 'ROW', fields: fs } : null;
  }).filter(Boolean);
  return { layout: walk(layout), groups };
}
export function publicFields(page, fields, { only = null, groups = new Set() } = {}) {
  const { top, tables } = visibleCodes(page, fields);
  const res = {};
  for (const c of top) if (!only || only.has(c)) res[c] = pickDef(fields[c]);
  for (const [c, cols] of tables) {
    if (only && !only.has(c)) continue;
    const sub = {};
    for (const cc of cols) sub[cc] = pickDef(fields[c].fields[cc]);
    res[c] = { ...pickDef(fields[c]), fields: sub };
  }
  for (const g of groups) if (fields[g] && fields[g].type === 'GROUP') res[g] = pickDef(fields[g]);
  return res;
}

// 添付の値を、保管庫が署名した識別子に置き換える(fileKey は返さない)
async function fileHandle(env, site, sid, page, recordId, f) {
  return sign(env, { v: 1, s: site.id, sid, p: page.id, r: String(recordId), k: String(f.fileKey), n: String(f.name || 'file').slice(0, 200), t: String(f.contentType || ''), exp: nowMs() + FILE_LINK_TTL_MS }, INFO.file);
}
async function withHandles(env, site, sid, page, shaped) {
  const conv = async (files) => Promise.all((Array.isArray(files) ? files : []).filter((f) => f && f.fileKey).map(async (f) => ({ name: String(f.name || ''), contentType: String(f.contentType || ''), size: String(f.size || ''), handle: await fileHandle(env, site, sid, page, shaped.id, f) })));
  for (const v of Object.values(shaped.values)) if (v.type === 'FILE') v.value = await conv(v.value);
  for (const t of Object.values(shaped.tables)) for (const r of t.rows) for (const v of Object.values(r.values)) if (v.type === 'FILE') v.value = await conv(v.value);
  return shaped;
}
// 添付の識別子を確かめて fileKey を取り出す(このセッション・このページ・このレコードのものだけ)。戻り値: { fileKey, name, contentType } | null
async function openFileHandle(env, site, sid, text, { pageId, recordId } = {}) {
  if (typeof text !== 'string' || !HANDLE_RE.test(text)) return null;
  const h = await verify(env, text, INFO.file);
  if (!h || h.v !== 1 || h.s !== site.id || h.sid !== sid || !(h.exp > nowMs()) || typeof h.k !== 'string' || !h.k) return null;
  if (pageId && h.p !== pageId) return null;
  if (recordId !== undefined && h.r !== String(recordId)) return null;
  return { pageId: h.p, recordId: h.r, fileKey: h.k, name: h.n, contentType: h.t };
}
async function openUploadHandle(env, site, sid, page, text) {
  if (typeof text !== 'string' || !HANDLE_RE.test(text)) return null;
  const h = await verify(env, text, INFO.upload);
  if (!h || h.v !== 1 || h.s !== site.id || h.sid !== sid || h.p !== page.id || !(h.exp > nowMs()) || typeof h.k !== 'string' || !h.k) return null;
  return { name: String(h.n || ''), size: Number(h.z) || 0, type: String(h.t || ''), fileKey: h.k };
}

const csrfOf = (env, { site, sid, page, recordId }) => sign(env, { s: site.id, sid, p: page.id, r: String(recordId), exp: nowMs() + CSRF_TTL_MS }, INFO.csrf);
async function csrfOk(env, text, { site, sid, page, recordId }) {
  const t = typeof text === 'string' ? await verify(env, text, INFO.csrf) : null;
  return !!t && t.s === site.id && t.sid === sid && t.p === page.id && t.r === String(recordId) && t.exp > nowMs();
}

// 詳細(画面の組み立て用): 閲覧を許した値・定義・レイアウト + 編集できる範囲 + フォームのトークン
async function detailBody(env, site, sid, o, record, ident) {
  const { page, fields } = o;
  const shaped = await withHandles(env, site, sid, page, viewRecord(page, fields, record, ident));
  const { layout, groups } = publicLayout(page, fields, o.layout);
  const tables = {};
  // テーブルごとに: 追加・編集で入力できる列 / 削除の扱い(remove = 行を消す・cancel = 取り消し列にチェック)/ メンバー表か(削除の確認の文面用)
  for (const code of Object.keys(shaped.tables)) {
    const t = page.settings.tables[code];
    tables[code] = { add: editableColumns(page, fields, code, t, { adding: true }), edit: editableColumns(page, fields, code, t), deleteMode: t.deleteMode === 'cancel' ? 'cancel' : 'remove', member: !!(page.settings.member && page.settings.member.table === code) };
  }
  const editable = { fields: editableFieldCodes(page, fields), tables };
  const canAny = shaped.canEdit || Object.values(shaped.tables).some((t) => t.canAdd || t.canEdit || t.canDel);
  return { record: shaped, fields: publicFields(page, fields, { groups }), layout, editable, csrf: canAny ? await csrfOf(env, { site, sid, page, recordId: shaped.id }) : '' };
}

// ---- GET /v1/pages/{p}/records?keyword=&offset= ----
//   本人のレコードの一覧(一覧のフィールドだけ)。検索なし・先頭で 1 件だけなら、その詳細(single)を返す(画面の 1 回の呼び出しで済むように)
export async function listRecords(env, ctx, site, v, slug, { keyword = '', offset = 0 } = {}) {
  const o = await openPage(env, site, slug, v.ident);
  if (o.error) return o.error;
  const { page, fields } = o;
  const kw = String(keyword || '').trim().slice(0, SEARCH_KEYWORD_MAX);
  const off = Math.max(0, parseInt(offset, 10) || 0);
  const fieldTypes = Object.fromEntries(Object.entries(fields).map(([c, d]) => [c, d.type]));
  const q = await reserveRecords(env, site, v.session.sid, LIST_PAGE_SIZE + 1);
  if (!q.ok) return fail(429, 'record_limit');
  const r = await o.k.getRecords(site.domain, page.app_id, o.token, { query: listQuery(page, v.ident, { keyword: kw, offset: off, fieldTypes }), fields: requestedFields(page, site) });
  if (!r.ok) {
    await q.settle(0);
    return fail(503, classifyPageError(r));
  }
  const hits = identMatches(r.records, page, v.ident);
  const single = !kw && off === 0 && hits.length === 1;
  const rows = hits.slice(0, LIST_PAGE_SIZE);
  await q.settle(rows.length);
  const m = (await identHash(env, v.ident)).slice(0, 16);
  ctx.waitUntil(logOp(env.DB, site.id, page.id, 'member', 'list', { m, n: rows.length }));
  if (single) return out(200, { ok: true, page: pageInfo(page), single: true, ...(await detailBody(env, site, v.session.sid, o, hits[0], v.ident)) });
  if (!kw && off === 0 && !hits.length) return fail(403, 'not_member');
  const listed = new Set(page.settings.list.fields);
  return out(200, {
    ok: true,
    page: pageInfo(page),
    fields: publicFields(page, fields, { only: listed }),
    // 一覧に出すのは一覧に出せる型だけ(添付・テーブルの値は詳細で。添付の fileKey を一覧に出さない)
    rows: rows.map((rec) => {
      const row = listRow(page, fields, viewRecord(page, fields, rec, v.ident));
      return { ...row, cells: row.cells.map((c) => (LISTABLE_TYPES.has(c.type) ? c : { ...c, value: null })) };
    }),
    keyword: kw,
    offset: off,
    hasMore: hits.length > LIST_PAGE_SIZE,
  });
}

// ---- GET /v1/pages/{p}/records/{id} ----
export async function getRecord(env, ctx, site, v, slug, recordId) {
  const o = await openPage(env, site, slug, v.ident);
  if (o.error) return o.error;
  const q = await reserveRecords(env, site, v.session.sid, 1);
  if (!q.ok) return fail(429, 'record_limit');
  const loaded = await loadRecord(env, site, o, v.ident, recordId);
  await q.settle(loaded.record ? 1 : 0);
  if (loaded.error) return loaded.error;
  ctx.waitUntil(logOp(env.DB, site.id, o.page.id, 'member', 'view', { m: (await identHash(env, v.ident)).slice(0, 16) }));
  return out(200, { ok: true, page: pageInfo(o.page), ...(await detailBody(env, site, v.session.sid, o, loaded.record, v.ident)) });
}

// ---- 編集の入力(画面側から届く JSON)を edit.js の形に ----
//   値は文字列か文字列の配列だけ。添付の削除はこのレコードの添付の識別子、追加はこのセッションでアップロードした識別子だけ
const strList = (x) => {
  if (typeof x === 'string') return [x.slice(0, TEXT_INPUT_MAX + 1)];
  if (Array.isArray(x) && x.length <= ARRAY_MAX && x.every((y) => typeof y === 'string')) return x.map((y) => y.slice(0, TEXT_INPUT_MAX + 1));
  if (x === null || x === undefined) return [];
  return null;
};
async function convertInput(env, site, sid, page, recordId, { values, removeFiles, addFiles }, prefix) {
  const input = {};
  const files = {};
  const obj = (x) => (x === undefined || x === null ? {} : x && typeof x === 'object' && !Array.isArray(x) ? x : null);
  const vs = obj(values);
  const rm = obj(removeFiles);
  const add = obj(addFiles);
  if (!vs || !rm || !add) return null;
  for (const [code, raw] of Object.entries(vs)) {
    const list = strList(raw);
    if (!list) return null;
    input[`${prefix}.${code}`] = list;
  }
  for (const [code, raw] of Object.entries(rm)) {
    const list = strList(raw);
    if (!list) return null;
    const keys = [];
    for (const h of list) {
      const f = await openFileHandle(env, site, sid, h, { pageId: page.id, recordId });
      if (!f) return null; // 署名の無い・別のレコード・別のセッションの識別子
      keys.push(f.fileKey);
    }
    input[`rm.${code}`] = keys;
  }
  for (const [code, raw] of Object.entries(add)) {
    const list = strList(raw);
    if (!list) return null;
    const got = [];
    for (const h of list) {
      const f = await openUploadHandle(env, site, sid, page, h);
      if (!f) return null;
      got.push(f);
    }
    files[`${prefix}.${code}`] = got;
  }
  return { input, files };
}
// 添付の操作 { keep, add } → kintone の値(残す fileKey + アップロード済みの fileKey)
const fileValue = (op) => ({ value: [...op.keep.map((x) => ({ fileKey: x.fileKey })), ...op.add.map((x) => ({ fileKey: x.fileKey }))] });

// ---- POST /v1/pages/{p}/records/{id}/save と /rows ----
//   save: { csrf, revision, fields?: { values, removeFiles, addFiles }, ops?: [{ op, table, row, values, removeFiles, addFiles }], lang }
//   rows: { csrf, revision, op, table, row, values, removeFiles, addFiles, lang }(行の操作 1 つ。revision は編集のときだけ照合する)
//   応答: { ok: true, revision } | { ok: false, error: 'csrf'|'conflict'|'input'|'forbidden'|'save'|…, errors?: { fields: { code: msg }, rows: { i: { col|_: msg } } } }
export async function saveRecord(env, ctx, site, v, slug, recordId, body, { single = false } = {}) {
  const lang = typeof body.lang === 'string' ? body.lang : site.settings.lang || 'ja';
  const M = msgFor(lang);
  const o = await openPage(env, site, slug, v.ident);
  if (o.error) return o.error;
  const { page, fields, k, token } = o;
  const sid = v.session.sid;
  const loaded = await loadRecord(env, site, o, v.ident, recordId);
  if (loaded.error) return loaded.error;
  const record = loaded.record;
  const id = String(record.$id.value);
  if (!(await csrfOk(env, body.csrf, { site, sid, page, recordId: id }))) return fail(403, 'csrf');
  const revision = String(record.$revision.value);
  const rawOps = single ? [{ op: body.op, table: body.table, row: body.row, values: body.values, removeFiles: body.removeFiles, addFiles: body.addFiles }] : Array.isArray(body.ops) ? body.ops : body.ops === undefined ? [] : null;
  if (!rawOps || rawOps.length > SAVE_OPS_MAX) return fail(400, 'invalid_body');
  const needRevision = single ? rawOps[0].op === 'edit' : true; // 行の追加・削除(1 つ)は最新の行に当てはめる
  if (needRevision && String(body.revision ?? '') !== revision) return fail(409, 'conflict');

  const shaped = viewRecord(page, fields, record, v.ident);
  const errors = { fields: {}, rows: {} };
  const rec = {};
  const fileSets = []; // { ops: { keep, add }, set(value) }
  let fieldPlan = null;
  if (!single && body.fields !== undefined) {
    if (!shaped.canEdit) return fail(403, 'forbidden');
    const conv = await convertInput(env, site, sid, page, id, body.fields || {}, 'f');
    if (!conv) return fail(400, 'invalid_body');
    fieldPlan = planFieldEdit({ page, fields, record, input: conv.input, files: conv.files, lang });
    Object.assign(errors.fields, fieldPlan.errors);
    Object.assign(rec, fieldPlan.values);
    for (const [code, op] of Object.entries(fieldPlan.fileOps)) fileSets.push({ ops: op, set: (val) => { rec[code] = val; } });
  }
  const byTable = new Map();
  for (let i = 0; i < rawOps.length; i++) {
    const x = rawOps[i];
    if (!x || typeof x !== 'object' || !['add', 'edit', 'del'].includes(x.op) || typeof x.table !== 'string' || !page.settings.tables[x.table] || !fields[x.table]) {
      errors.rows[i] = { _: M.forbidden };
      continue;
    }
    const conv = await convertInput(env, site, sid, page, id, x, 'c');
    if (!conv) return fail(400, 'invalid_body');
    if (!byTable.has(x.table)) byTable.set(x.table, []);
    byTable.get(x.table).push({ i, op: x.op, rowId: x.row === undefined || x.row === null ? null : String(x.row), input: conv.input, files: conv.files });
  }
  const comments = [];
  for (const [tbl, ops] of byTable) {
    const plan = planTableOps({ page, fields, record, tableCode: tbl, ops, email: v.ident, lang });
    for (const [i, e] of Object.entries(plan.errors)) errors.rows[ops[i].i] = e;
    rec[tbl] = { value: plan.tableValue };
    for (const r of plan.results) {
      if (r.entry) for (const [col, op] of Object.entries(r.fileOps)) fileSets.push({ ops: op, set: (val) => { r.entry.value = { ...(r.entry.value || {}), [col]: val }; } });
      if (r.comment) comments.push({ tbl, r });
    }
  }
  if (Object.keys(errors.fields).length || Object.keys(errors.rows).length) return fail(400, 'input', { errors });
  if (!Object.keys(rec).length) return out(200, { ok: true, noop: true, revision });
  for (const f of fileSets) f.set(fileValue(f.ops));
  const upd = page.settings.record.updaterField;
  if (upd && fields[upd] && fields[upd].type === 'SINGLE_LINE_TEXT') rec[upd] = { value: identValue(v.ident) };

  const put = await k.putRecord(site.domain, page.app_id, token, { id, revision, record: rec });
  const m = (await identHash(env, v.ident)).slice(0, 16);
  const nFiles = fileSets.reduce((n, f) => n + f.ops.add.length, 0);
  if (!put.ok) {
    ctx.waitUntil(logOp(env.DB, site.id, page.id, 'member', 'save_failed', { m, code: put.code || null, conflict: !!put.conflict }));
    if (put.conflict) return fail(409, 'conflict');
    return fail(502, 'save', { message: String(put.message || '').slice(0, 300) });
  }
  ctx.waitUntil(logOp(env.DB, site.id, page.id, 'member', 'save', { m, fields: fieldPlan ? fieldPlan.codes.length : 0, ops: rawOps.length, files: nFiles }));
  // 操作の記録(レコードのコメント)。文面は保管庫が作る(画面側からは受け取らない)。失敗しても保存は成功扱い
  for (const { tbl, r } of comments) {
    const tableDef = fields[tbl];
    const t = page.settings.tables[tbl];
    const kind = r.comment.kind;
    let rowForSummary = r.row;
    if (kind === 'member_add') rowForSummary = { value: { ...(r.entry.value || {}) } };
    if (kind === 'member_edit') rowForSummary = { value: { ...(r.row.value || {}), ...(r.entry.value || {}) } };
    const text = commentText(site.settings.lang || 'ja', { kind, email: v.ident, tableLabel: tableDef.label || tbl, summary: summarizeRow(tableDef, t, rowForSummary, r.comment.cols) });
    ctx.waitUntil(k.addComment(site.domain, page.app_id, token, id, text).then((x) => { if (!x.ok) console.error(`[comment ${page.id}] ${x.status} ${x.code}`); }).catch((e) => console.error(`[comment] ${e.message}`)));
  }
  return out(200, { ok: true, revision: put.revision });
}

// ---- 添付 ----
// このページで、このメンバーが添付を入力できるところがあるか(アップロードを受け付ける条件)
function canUploadTo(page, fields) {
  if (editableFieldCodes(page, fields).some((c) => fields[c].type === 'FILE')) return true;
  return Object.entries(page.settings.tables).some(([code, t]) => (t.all.add || t.all.edit || t.owner.edit) && fields[code] && editableColumns(page, fields, code, t, { adding: true }).some((c) => fields[code].fields[c].type === 'FILE'));
}
// POST /v1/pages/{p}/files  本文はファイルそのもの。X-File-Name(URL エンコード)・Content-Type。kintone へ中継するだけで保存しない
//   応答: { ok: true, upload: { handle, name, size } }(handle は保存の addFiles に使う)
export async function uploadFile(env, site, v, slug, request, { lang } = {}) {
  const M = msgFor(lang || site.settings.lang || 'ja');
  const o = await openPage(env, site, slug, v.ident);
  if (o.error) return o.error;
  if (!canUploadTo(o.page, o.fields)) return fail(403, 'forbidden');
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > FILE_MAX_BYTES) return fail(413, 'too_large', { message: M.fileSize(Math.round(FILE_MAX_BYTES / 1024 / 1024)) });
  let name = '';
  try {
    name = decodeURIComponent(String(request.headers.get('X-File-Name') || ''));
  } catch { /* 不正な形式 */ }
  name = name.replace(/[\x00-\x1f\x7f/\\]/g, '_').trim().slice(0, 200);
  if (!name) return fail(400, 'invalid_body');
  const bad = fileAllowedBy(o.page.settings.attachments, name);
  if (bad === 'blocked') return fail(400, 'file_blocked', { message: M.fileBlocked });
  if (bad === 'ext') return fail(400, 'file_ext', { message: M.fileExt((allowedExtensionsOf(o.page.settings.attachments) || []).join(', ')) });
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength) return fail(400, 'invalid_body');
  if (bytes.byteLength > FILE_MAX_BYTES) return fail(413, 'too_large', { message: M.fileSize(Math.round(FILE_MAX_BYTES / 1024 / 1024)) });
  const type = String(request.headers.get('Content-Type') || '').split(';')[0].trim().slice(0, 100) || 'application/octet-stream';
  const up = await o.k.uploadFile(site.domain, o.token, { name, type, bytes });
  if (!up.ok) return fail(502, 'upload_failed');
  const handle = await sign(env, { v: 1, s: site.id, sid: v.session.sid, p: o.page.id, k: up.fileKey, n: name, z: bytes.byteLength, t: type, exp: nowMs() + UPLOAD_HANDLE_TTL_MS }, INFO.upload);
  return out(200, { ok: true, upload: { handle, name, size: bytes.byteLength } });
}

// GET /v1/files/{handle}  添付のダウンロード(このセッションに見せたレコードの添付だけ)。本文をそのまま中継する(保存しない)
export async function downloadFile(env, site, v, handle) {
  const notFound = () => new Response(JSON.stringify({ ok: false, error: 'not_found' }), { status: 404, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  const h = await openFileHandle(env, site, v.session.sid, handle);
  if (!h) return notFound();
  const page = await getPageById(env.DB, h.pageId);
  if (!page || page.site_id !== site.id || !usablePage(page) || !pageAcceptsIdent(page, v.ident)) return notFound();
  const token = await pageToken(env, page).catch(() => null);
  if (!token) return notFound();
  const res = await kintoneFor(env, site, page).downloadFile(site.domain, token, h.fileKey).catch(() => null);
  if (!res || !res.ok) return notFound();
  const ct = String(h.contentType || 'application/octet-stream');
  const img = /^image\/(png|jpeg|gif|webp)$/.test(ct);
  const name = String(h.name || 'file').replace(/["\r\n]/g, '_');
  return new Response(res.body, {
    status: 200,
    headers: {
      'Content-Type': img ? ct : 'application/octet-stream',
      'Content-Disposition': `${img ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(name)}`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    },
  });
}

// ---- 自己登録(MYPAGE 設計 §19)----
// POST /v1/signup/form { token }  登録画面の組み立て用(入力させるフィールドの定義・同意文)
// POST /v1/signup { token, values, lang }  追加専用トークンで本人のレコードを 1 件だけ作り、そのままログインする
//   トークンは本人確認の直後に保管庫が署名したもの(session.js signSignup)。照合に使うフィールドにはトークンの本人の識別子だけを入れる
async function openSignup(env, site, token) {
  const t = await verifySignup(env, site, token);
  if (!t) return { error: fail(403, 'signup_expired') };
  const ident = asIdent({ kind: t.k, id: t.e, name: t.n });
  const pages = await listPages(env.DB, site.id);
  const page = pages.find((p) => p.id === t.p);
  if (!page || !signupCapable(page, ident)) return { error: fail(404, 'page_stopped') };
  const viewToken = await pageToken(env, page).catch(() => null);
  if (!viewToken) return { error: fail(503, 'token') };
  const k = kintoneFor(env, site, page);
  const def = await formDef(env, site, page, k, viewToken);
  if (!def.ok) return { error: fail(503, classifyPageError(def.error)) };
  return { t, ident, pages, page, k, fields: def.fields };
}
export async function signupForm(env, site, body) {
  const s = await openSignup(env, site, body.token);
  if (s.error) return s.error;
  const codes = signupFieldCodes(s.page, s.fields);
  return out(200, { ok: true, page: { slug: s.page.slug, name: s.page.settings.name || '' }, codes, fields: Object.fromEntries(codes.map((c) => [c, pickDef(s.fields[c])])), consent: s.page.settings.signup.consent || '', member: { kind: s.ident.kind, label: isLine(s.ident) ? `LINE: ${s.ident.name || s.ident.id}` : s.ident.id } });
}
export async function signup(env, ctx, site, body) {
  const s = await openSignup(env, site, body.token);
  if (s.error) return s.error;
  const { t, ident, pages, page, k, fields } = s;
  const method = t.k === 'line' ? 'line' : 'email';
  // 既にレコードがあれば作らない(二重登録の防止)
  if ((await checkMembership(env, site, [page], ident)).length) return completeLogin(env, site, ctx, { ident, method, pageIds: [page.id], next: `/${page.slug}/`, pages });
  const values = body.values && typeof body.values === 'object' && !Array.isArray(body.values) ? body.values : {};
  const input = {};
  for (const [code, raw] of Object.entries(values)) {
    const list = strList(raw);
    if (!list) return fail(400, 'invalid_body');
    input[`f.${code}`] = list;
  }
  const plan = planSignup({ page, fields, input, ident, lang: typeof body.lang === 'string' ? body.lang : site.settings.lang || 'ja' });
  if (!plan.ok) return fail(400, 'input', { errors: plan.errors });
  const addToken = await pageAddToken(env, page).catch(() => null);
  if (!addToken) return fail(404, 'page_stopped');
  // 1 つのトークンで作るレコードは 1 件だけ(並列に送られても)。作れなかったときは印を外して、やり直せるようにする
  const mark = (await sha256Hex(`signup:${body.token}`)).slice(0, 32);
  const got = await env.DB.prepare("INSERT INTO codes (id, site_id, kind, hash, data, attempts, expires_at) VALUES (?, ?, 'signup_used', '', '{}', 0, ?) ON CONFLICT(id) DO NOTHING RETURNING id").bind(mark, site.id, new Date(t.exp).toISOString()).first();
  if (!got) return fail(409, 'signup_in_progress');
  const r = await k.postRecord(site.domain, page.app_id, addToken, plan.record);
  const h = (await identHash(env, ident)).slice(0, 16);
  if (!r.ok) {
    await deleteCode(env.DB, mark);
    await logOp(env.DB, site.id, page.id, 'member', 'signup_failed', { m: h, code: r.code || null });
    return fail(502, 'signup_failed', { kind: classifyPageError(r) });
  }
  await logOp(env.DB, site.id, page.id, 'member', 'signup', { m: h });
  const pageIds = await checkMembership(env, site, scopePages(site, pages, page), ident);
  return completeLogin(env, site, ctx, { ident, method, pageIds: pageIds.length ? pageIds : [page.id], next: `/${page.slug}/`, pages });
}

// ---- LINE 連携(MYPAGE 設計 §4.2.10)----
// POST /v1/line/link { c }  連携用リンク(社内が発行)を開いた画面用 → { valid }
export async function lineLinkInfo(env, site, body) {
  const m = STATE_RE.exec(String(body.c || ''));
  const row = m ? await getCode(env.DB, m[1], 'line_link') : null;
  const valid = !!row && row.site_id === site.id && Date.parse(row.expires_at) > nowMs() && timingSafeEqual(await hmacHex(env, m[2], INFO.code), row.hash) && lineConfigured(site);
  return out(200, { ok: true, valid });
}

// POST /v1/line/connect { ticket }  LINE の完了(/v1/login/line/finish の result: 'line_connect')の後、サイトのホストから呼ぶ
//   メンバー自身の連携: 開始と同じセッション(X-Mypage-Session)が要る。本人のレコードの LINE 連携 ID に書く(他の LINE が入っていれば上書きしない)
//     → { result: 'connected', n }(セッションはそのまま)
//   連携用リンク: リンクのレコード(メンバー表なら該当の行)に書き、LINE の識別子でログインする → ログインの結果(session.js)
export async function lineConnect(env, ctx, site, body, rawSession) {
  const m = STATE_RE.exec(String(body.ticket || ''));
  const row = m ? await takeCode(env.DB, m[1], 'line_done') : null;
  if (!row || row.site_id !== site.id || Date.parse(row.expires_at) < nowMs() || !timingSafeEqual(await hmacHex(env, m[2], INFO.code), row.hash)) return fail(400, 'ticket_invalid');
  const d = row.data;
  const lineIdent = asIdent({ kind: 'line', id: d.id, name: d.name });
  if (!lineIdent.id) return fail(400, 'ticket_invalid');
  const pages = await listPages(env.DB, site.id);
  if (d.cn) {
    const v = await verifySession(env, site, rawSession || '');
    if (!v.ok || v.session.sid !== d.cn.sid || isLine(v.ident) || v.ident.id !== d.cn.e || !site.settings.line.selfLink) return fail(403, 'session_mismatch');
    const n = await connectLineForMember(env, site, pages, v.ident, lineIdent);
    await logOp(env.DB, site.id, null, 'member', 'line_connect', { n, m: (await identHash(env, v.ident)).slice(0, 16) });
    return out(200, { ok: true, result: 'connected', n });
  }
  if (d.lk) {
    const linked = await consumeLineLink(env, site, pages, d.lk, lineIdent);
    if (!linked.ok) return fail(400, 'link_invalid');
    const next = `/${linked.page.slug}/${linked.recordId}`;
    await logOp(env.DB, site.id, linked.page.id, 'member', 'line_link', { m: (await identHash(env, lineIdent)).slice(0, 16) });
    const pageIds = await checkMembership(env, site, scopePages(site, pages, entryPageOf(pages, next)), lineIdent);
    return afterVerify(env, site, ctx, { ident: lineIdent, method: 'line', pageIds, pages, next, su: false });
  }
  return fail(400, 'ticket_invalid');
}

// 連携用リンクの消費と書き込み。戻り値: { ok: true, page, recordId } | { ok: false }
async function consumeLineLink(env, site, pages, text, lineIdent) {
  const m = STATE_RE.exec(String(text || ''));
  if (!m) return { ok: false };
  const row = await takeCode(env.DB, m[1], 'line_link'); // 1 回限り
  if (!row || row.site_id !== site.id || Date.parse(row.expires_at) < nowMs() || !timingSafeEqual(await hmacHex(env, m[2], INFO.code), row.hash)) return { ok: false };
  const page = pages.find((p) => p.id === row.data.p);
  if (!page || !usablePage(page) || !page.settings.line || !page.settings.line.field) return { ok: false };
  const ok = await writeLineId(env, site, page, { recordId: String(row.data.r), rowId: row.data.row ? String(row.data.row) : null, lineId: lineIdent.id });
  return ok ? { ok: true, page, recordId: String(row.data.r) } : { ok: false };
}

// メンバー自身の連携: ログイン中の識別子(メール)で照合できるレコードに LINE 連携 ID を書く。戻り値: 書いたレコード数
export async function connectLineForMember(env, site, pages, cur, lineIdent) {
  let n = 0;
  for (const page of pages) {
    if (!usablePage(page) || !page.settings.line || !page.settings.line.field) continue;
    try {
      const token = await pageToken(env, page);
      if (!token) continue;
      const k = kintoneFor(env, site, page);
      const spec = matchSpec(page, cur);
      const r = await k.getRecords(site.domain, page.app_id, token, { query: membershipQuery(page, cur).replace(/ limit 1$/, ` limit ${LAST_LOGIN_MAX_RECORDS}`), fields: ['$id', spec.table || spec.field] });
      if (!r.ok) continue;
      for (const rec of identMatches(r.records, page, cur)) {
        let rowId = null;
        if (page.settings.member.table) {
          const rows = rec[page.settings.member.table] && Array.isArray(rec[page.settings.member.table].value) ? rec[page.settings.member.table].value : [];
          const hit = rows.find((x) => x && x.value && x.value[spec.field] && normalizeEmail(x.value[spec.field].value) === cur.id);
          if (!hit) continue;
          rowId = String(hit.id);
        }
        if (await writeLineId(env, site, page, { recordId: String(rec.$id.value), rowId, lineId: lineIdent.id, onlyEmpty: true }, k, token)) n++;
      }
    } catch (err) {
      console.error(`[line connect ${page.id}] ${err.message}`);
    }
  }
  return n;
}

// LINE 連携 ID をレコード(またはメンバー表の行)に書く。revision は付けない。他の行は id だけで送る(MYPAGE 設計 §13.1 S3)。
//   onlyEmpty: 別の LINE のユーザー ID が入っていれば書かない(メンバー自身の連携。乗っ取ったセッションで本人の LINE を差し替えさせない)
export async function writeLineId(env, site, page, { recordId, rowId, lineId, onlyEmpty = false }, k, token) {
  try {
    token = token || (await pageToken(env, page));
    if (!token) return false;
    k = k || kintoneFor(env, site, page);
    const f = page.settings.line.field;
    const table = page.settings.member.table;
    const r = await k.getRecords(site.domain, page.app_id, token, { query: `$id = ${Number(recordId)} limit 1`, fields: ['$id', table || f] });
    if (!r.ok || !r.records.length) return false;
    const taken = (cell) => onlyEmpty && !!cell && String(cell.value || '').trim() !== '' && String(cell.value).trim() !== lineId;
    let record;
    if (table) {
      if (!rowId) return false;
      const rows = r.records[0][table] && Array.isArray(r.records[0][table].value) ? r.records[0][table].value : [];
      const target = rows.find((x) => String(x.id) === rowId);
      if (!target || taken(target.value && target.value[f])) return false;
      record = { [table]: { value: rows.map((x) => (String(x.id) === rowId ? { id: String(x.id), value: { [f]: { value: lineId } } } : { id: String(x.id) })) } };
    } else {
      if (taken(r.records[0][f])) return false;
      record = { [f]: { value: lineId } };
    }
    const put = await k.putRecord(site.domain, page.app_id, token, { id: recordId, record });
    return put.ok;
  } catch (err) {
    console.error(`[line write ${page.id}] ${err.message}`);
    return false;
  }
}

// ---- メンバー証(サイトで 1 つ。MYPAGE 設計 §18)の対象。/v1/me/pages で返す(取得は一覧・詳細の API で)----
export function cardOf(site, pages) {
  const c = site.settings.card;
  if (!c || !c.enabled || !c.page) return null;
  const page = pages.find((p) => p.id === c.page);
  if (!page || !usablePage(page)) return null;
  const r = cardForPage(c, page);
  return r ? { page: page.slug, field: r.field, fields: r.fields, name: r.name } : null;
}
