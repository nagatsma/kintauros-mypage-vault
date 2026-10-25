// 複製元: kintauros-plugins の packages/worker-kit/src/kintone.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
// kintone REST API の呼び出し(Worker → 顧客の kintone)。createKintone({ userAgent, timeoutMs, fileTimeoutMs, fetchImpl }) で
// Worker ごとの設定を束ねる。呼び出し先は呼び出し側が normalizeKintoneDomain で正規化した契約ドメインに限る(SSRF 防止)。
// 送信本文・トークン・レコードの内容をログに出さない(SERVICE-POLICY §7-10)。
//   publish-worker: 追加専用トークンでの POST record / POST file と、トークン登録時の権限検証(閲覧・編集・削除・アプリ管理ができないことの確認)
//   mypage-worker : 閲覧+編集のトークンでの GET records / PUT record / GET・POST file / フォーム定義と、権限検証(閲覧+編集だけ)
export const DEFAULT_TIMEOUT_MS = 8000;
export const DEFAULT_FILE_TIMEOUT_MS = 30000;

// エラー応答の分類。retryable: kintone 側の一時的な問題(429・5xx・ネットワーク・メンテナンス)
export function classifyError(r) {
  const code = (r.json && r.json.code) || '';
  const message = (r.json && r.json.message) || (r.error ? `network: ${r.error}` : `HTTP ${r.status}`);
  const retryable = r.status === 0 || r.status === 429 || r.status >= 500 || (r.status === 503 && !r.json);
  return { status: r.status, code, message: String(message).slice(0, 300), retryable };
}

const q = (v) => encodeURIComponent(String(v));

export function createKintone({ userAgent = 'kintauros-worker', timeoutMs = DEFAULT_TIMEOUT_MS, fileTimeoutMs = DEFAULT_FILE_TIMEOUT_MS, fetchImpl } = {}) {
  const doFetch = (url, init) => (fetchImpl || globalThis.fetch)(url, init);
  const baseOf = (domain) => `https://${domain}`;

  // 生の Response を返す(添付のストリーミング用)。呼び出し側が本文を読む
  async function callRaw(domain, token, path, method, body, ms = timeoutMs, meta = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      const headers = { 'X-Cybozu-API-Token': token, 'User-Agent': userAgent };
      const isForm = typeof FormData !== 'undefined' && body instanceof FormData; // multipart(file.json)は fetch が境界付きの Content-Type を付ける
      if (body !== undefined && !isForm) headers['Content-Type'] = 'application/json';
      const res = await doFetch(`${baseOf(domain)}/k/v1/${path}`, { method, headers, body: body === undefined ? undefined : isForm ? body : JSON.stringify(body), signal: ctrl.signal, kintauros: meta });
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  async function call(domain, token, path, method, body, ms = timeoutMs, meta = {}) {
    try {
      const res = await callRaw(domain, token, path, method, body, ms, meta);
      const text = await res.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch { /* HTML(メンテナンス等) */ }
      return { status: res.status, json };
    } catch (err) {
      return { status: 0, json: null, error: String((err && err.message) || err) };
    }
  }

  // 追加専用トークンの権限検証(publish F4。SERVICE-POLICY §4-5 条件 1 の例外)。閲覧・編集・削除・アプリ管理のどれかができるトークンは拒否する。
  // 試験は checkAddOnly と同じ(データを作らず・変えない)。追加できることの確認は設定画面の「テスト送信」が担うので、ここでは追加の試験をしない
  // 戻り値: { ok: true } | { ok: false, error: 'unreachable'|'token_invalid'|'token_not_enabled'|'token_can_read'|'token_can_edit'|'token_can_delete'|'token_can_manage'|'unexpected', detail }
  async function checkTokenPermissions(domain, appId, token) {
    const r = await checkAddOnly(domain, appId, token, null);
    return r.error === 'cannot_test_add' ? { ok: true } : r; // cannot_test_add = 閲覧・編集・削除・アプリ管理の試験をすべて通過した
  }

  // 「閲覧+編集だけ」のトークンの権限検証(mypage。設計 docs/MYPAGE-DESIGN-2026-09.md §13.1 S1)。どの試験もデータを作らず・変えない。
  //   閲覧: GET records(limit 1)が 200 / 編集: 存在しないレコード番号への PUT が 404 GAIA_RE01
  //   追加: 必ず検証エラーになる本文の POST が 403(400 CB_VA01 なら追加できてしまう) / 削除: 存在しない番号の DELETE が 403(404 なら削除できる)
  //   アプリ管理: GET preview/app/form/fields が 403
  // 戻り値: { ok: true, fields } | { ok: false, error: 'unreachable'|'token_invalid'|'token_not_enabled'|'token_cannot_read'|'token_cannot_edit'|
  //          'token_can_add'|'token_can_delete'|'token_can_manage'|'cannot_test_add'|'unexpected', detail }
  async function checkViewEditOnly(domain, appId, token) {
    const NONE = '2147483647'; // 存在しないレコード番号(kintone の上限側)
    const bad = (r, error) => ({ ok: false, error, detail: `${r.status} ${(r.json && r.json.code) || r.error || ''}`.trim() });
    const code = (r) => (r.json && r.json.code) || '';
    const denied = (r) => r.status === 403 || code(r) === 'GAIA_NO01' || code(r) === 'CB_NO02';

    const read = await call(domain, token, `records.json?app=${q(appId)}&query=${q('limit 1')}&fields[0]=${q('$id')}`, 'GET');
    if (read.status === 0) return { ok: false, error: 'unreachable', detail: read.error };
    if (read.status === 401 || code(read) === 'CB_AU01') return bad(read, 'token_invalid');
    if (code(read) === 'GAIA_IA02') return bad(read, 'token_not_enabled'); // トークンを保存した後の「アプリを更新」忘れ・別のアプリのトークン
    if (denied(read)) return bad(read, 'token_cannot_read');
    if (read.status !== 200) return bad(read, 'unexpected');

    const edit = await call(domain, token, 'record.json', 'PUT', { app: appId, id: NONE, record: {} });
    if (denied(edit)) return bad(edit, 'token_cannot_edit');
    if (!(edit.status === 404 || code(edit) === 'GAIA_RE01')) return bad(edit, 'unexpected');

    const del = await call(domain, token, `records.json?app=${q(appId)}&ids[0]=${NONE}`, 'DELETE');
    if (del.status === 404 || code(del) === 'GAIA_RE01' || del.status === 200) return bad(del, 'token_can_delete');
    if (!denied(del)) return bad(del, 'unexpected');

    const manage = await call(domain, token, `preview/app/form/fields.json?app=${q(appId)}`, 'GET');
    if (manage.status === 200) return bad(manage, 'token_can_manage');
    if (!denied(manage)) return bad(manage, 'unexpected');

    // 追加の試験: フィールド定義から「必ず検証エラーになる本文」を組み立てる(閲覧できるトークンは運用環境の定義を読める)
    const fields = await call(domain, token, `app/form/fields.json?app=${q(appId)}`, 'GET');
    if (fields.status !== 200 || !fields.json || !fields.json.properties) return bad(fields, 'unexpected');
    const body = invalidRecordBody(fields.json.properties);
    if (!body) return { ok: false, error: 'cannot_test_add', detail: 'no field suitable for a validation-error probe' };
    const add = await call(domain, token, 'record.json', 'POST', { app: appId, record: body });
    if (denied(add)) return { ok: true, fields: fields.json.properties };
    if (add.status === 200) return { ok: false, error: 'token_can_add', detail: `${add.status} record_created:${(add.json && add.json.id) || ''}` }; // 想定外(検証エラーになるはずの本文)。起きたら設定画面で削除を案内する
    return bad(add, 'token_can_add');
  }

  // 「追加だけ」のトークンの権限検証(mypage の自己登録。設計 docs/MYPAGE-DESIGN-2026-09.md §19)。データを作らず・変えない。
  //   閲覧: GET records が 403 / 編集: 存在しない番号への PUT が 403 / 削除: 存在しない番号の DELETE が 403 / アプリ管理: preview が 403
  //   追加: 必ず検証エラーになる本文の POST が 400 CB_VA01(403 なら追加できない)。本文は呼び出し側が渡す(閲覧できないトークンはフィールド定義を読めない)
  // 戻り値: { ok: true } | { ok: false, error: 'unreachable'|'token_invalid'|'token_not_enabled'|'token_can_read'|'token_can_edit'|'token_can_delete'|'token_can_manage'|'token_cannot_add'|'unexpected', detail }
  async function checkAddOnly(domain, appId, token, invalidBody) {
    const NONE = '2147483647';
    const bad = (r, error) => ({ ok: false, error, detail: `${r.status} ${(r.json && r.json.code) || r.error || ''}`.trim() });
    const code = (r) => (r.json && r.json.code) || '';
    const denied = (r) => r.status === 403 || code(r) === 'GAIA_NO01' || code(r) === 'CB_NO02';
    const read = await call(domain, token, `records.json?app=${q(appId)}&query=${q('limit 1')}&fields[0]=${q('$id')}`, 'GET');
    if (read.status === 0) return { ok: false, error: 'unreachable', detail: read.error };
    if (read.status === 401 || code(read) === 'CB_AU01') return bad(read, 'token_invalid');
    if (code(read) === 'GAIA_IA02') return bad(read, 'token_not_enabled');
    if (read.status === 200) return bad(read, 'token_can_read');
    if (!denied(read)) return bad(read, 'unexpected');
    const edit = await call(domain, token, 'record.json', 'PUT', { app: appId, id: NONE, record: {} });
    if (edit.status === 404 || code(edit) === 'GAIA_RE01' || edit.status === 200) return bad(edit, 'token_can_edit');
    if (!denied(edit)) return bad(edit, 'unexpected');
    const del = await call(domain, token, `records.json?app=${q(appId)}&ids[0]=${NONE}`, 'DELETE');
    if (del.status === 404 || code(del) === 'GAIA_RE01' || del.status === 200) return bad(del, 'token_can_delete');
    if (!denied(del)) return bad(del, 'unexpected');
    const manage = await call(domain, token, `preview/app/form/fields.json?app=${q(appId)}`, 'GET');
    if (manage.status === 200) return bad(manage, 'token_can_manage');
    if (!denied(manage)) return bad(manage, 'unexpected');
    if (!invalidBody) return { ok: false, error: 'cannot_test_add', detail: 'no probe body' };
    const add = await call(domain, token, 'record.json', 'POST', { app: appId, record: invalidBody });
    if (denied(add)) return bad(add, 'token_cannot_add');
    if (add.status === 400 && code(add) === 'CB_VA01') return { ok: true };
    if (add.status === 200) return { ok: false, error: 'unexpected', detail: `record_created:${(add.json && add.json.id) || ''}` };
    return bad(add, 'unexpected');
  }

  // POST /k/v1/file(添付)。公式仕様では必要なアクセス権「なし」で API トークン認証可。fileKey は 3 日で失効するので登録の直前に呼ぶ
  async function uploadFile(domain, token, { name, type, bytes }) {
    const fd = new FormData();
    fd.append('file', new Blob([bytes], { type: type || 'application/octet-stream' }), String(name || 'image').slice(0, 200) || 'image');
    const r = await call(domain, token, 'file.json', 'POST', fd, fileTimeoutMs, { file: true });
    if (r.status === 200 && r.json && r.json.fileKey) return { ok: true, fileKey: String(r.json.fileKey) };
    return { ok: false, ...classifyError(r) };
  }

  // GET /k/v1/file(添付のダウンロード)。Response をそのまま返す(呼び出し側がストリームで中継し、保存しない)
  async function downloadFile(domain, token, fileKey) {
    return callRaw(domain, token, `file.json?fileKey=${q(fileKey)}`, 'GET', undefined, fileTimeoutMs, { file: true });
  }

  // POST /k/v1/record。戻り値: { ok: true, recordId, revision } | { ok: false, ...classifyError }
  async function postRecord(domain, appId, token, record) {
    const r = await call(domain, token, 'record.json', 'POST', { app: appId, record }, timeoutMs, { app: appId });
    if (r.status === 200 && r.json && r.json.id) return { ok: true, recordId: String(r.json.id), revision: String(r.json.revision || '') };
    return { ok: false, ...classifyError(r) };
  }

  // GET /k/v1/records(fields で取得列を絞る)。戻り値: { ok: true, records, totalCount } | { ok: false, ...classifyError }
  async function getRecords(domain, appId, token, { query, fields, totalCount = false } = {}) {
    const params = [`app=${q(appId)}`];
    if (query) params.push(`query=${q(query)}`);
    (fields || []).forEach((f, i) => params.push(`fields[${i}]=${q(f)}`));
    if (totalCount) params.push('totalCount=true');
    const r = await call(domain, token, `records.json?${params.join('&')}`, 'GET', undefined, timeoutMs, { app: appId });
    if (r.status === 200 && r.json && Array.isArray(r.json.records)) return { ok: true, records: r.json.records, totalCount: r.json.totalCount == null ? null : Number(r.json.totalCount) };
    return { ok: false, ...classifyError(r) };
  }

  // PUT /k/v1/record(revision 必須)。戻り値: { ok: true, revision } | { ok: false, ...classifyError, conflict }
  async function putRecord(domain, appId, token, { id, record, revision }) {
    const r = await call(domain, token, 'record.json', 'PUT', { app: appId, id, revision, record }, timeoutMs, { app: appId });
    if (r.status === 200 && r.json) return { ok: true, revision: String(r.json.revision || '') };
    const e = classifyError(r);
    return { ok: false, ...e, conflict: e.code === 'GAIA_CO02' };
  }

  // POST /k/v1/record/comment.json(レコードのコメント。閲覧+編集のトークンで書ける。revision は変わらない。mypage 設計 §13.1 S15)
  async function addComment(domain, appId, token, recordId, text) {
    const r = await call(domain, token, 'record/comment.json', 'POST', { app: appId, record: recordId, comment: { text: String(text).slice(0, 65535) } }, timeoutMs, { app: appId });
    if (r.status === 200 && r.json) return { ok: true, id: String(r.json.id || '') };
    return { ok: false, ...classifyError(r) };
  }

  async function getFormFields(domain, appId, token) {
    const r = await call(domain, token, `app/form/fields.json?app=${q(appId)}`, 'GET');
    if (r.status === 200 && r.json && r.json.properties) return { ok: true, properties: r.json.properties, revision: String(r.json.revision || '') };
    return { ok: false, ...classifyError(r) };
  }
  async function getFormLayout(domain, appId, token) {
    const r = await call(domain, token, `app/form/layout.json?app=${q(appId)}`, 'GET');
    if (r.status === 200 && r.json && Array.isArray(r.json.layout)) return { ok: true, layout: r.json.layout, revision: String(r.json.revision || '') };
    return { ok: false, ...classifyError(r) };
  }

  return { call, callRaw, classifyError, checkTokenPermissions, checkViewEditOnly, checkAddOnly, uploadFile, downloadFile, postRecord, getRecords, putRecord, addComment, getFormFields, getFormLayout };
}

// 「必ず検証エラーになる本文」をフィールド定義から組み立てる(追加権限の試験。レコードは作られない)。
// 選択肢に無い値 → 数値・日付・時刻に文字 → 文字数上限超え(1 行文字列は kintone の上限 64,000 文字を超える値)の順に探す
export function invalidRecordBody(properties) {
  const list = Object.values(properties || {});
  const pick = (types) => list.find((p) => p && types.includes(p.type));
  let f = pick(['DROP_DOWN', 'RADIO_BUTTON']);
  if (f) return { [f.code]: { value: '__kintauros_invalid_option__' } };
  f = pick(['CHECK_BOX', 'MULTI_SELECT']);
  if (f) return { [f.code]: { value: ['__kintauros_invalid_option__'] } };
  f = pick(['NUMBER', 'DATE', 'DATETIME', 'TIME']);
  if (f) return { [f.code]: { value: 'not-a-value' } };
  f = list.find((p) => p && p.type === 'LINK' && p.protocol === 'MAIL');
  if (f) return { [f.code]: { value: 'not-an-email' } };
  f = list.find((p) => p && p.type === 'SINGLE_LINE_TEXT' && p.maxLength && Number(p.maxLength) > 0);
  if (f) return { [f.code]: { value: 'x'.repeat(Number(f.maxLength) + 1) } };
  f = pick(['SINGLE_LINE_TEXT']);
  if (f) return { [f.code]: { value: 'x'.repeat(64001) } };
  return null;
}
