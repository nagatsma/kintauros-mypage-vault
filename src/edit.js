// 編集の検証(VAULT 設計 §6.2-3。mypage-worker の edit.js を移したもの。純関数。D1・kintone に触らない)。
//   原則: 画面側から受け取るのは「操作」(このフィールドをこの値に / 行 id X を削除 / この内容の行を追加 / 行 id Y のこの列をこう変える)の入力値だけ。
//   保管庫が直前に本人の条件で取り直した最新のレコードに操作を当てはめて PUT の本文を組み立てる(テーブルは既存の行を id 付きで全部含める)。
//   ここを通さない値を kintone に送らない。設定で「編集」を付けたフィールド・列だけを受け付け、それ以外の入力は捨てる。
//   照合に使うフィールド(メンバーのメールアドレス・LINE 連携 ID。メンバー表の列を含む)は書き換えさせない(既存の行も他人の行も)。
//   例外はメンバー表の行の追加(契約者が「追加」を許したときの招待。§4.5.1 の 5)で、新しい行にだけメールアドレスを入れられる。LINE 連携 ID は入れられない
//   kintone 標準の検証(必須・文字数・数値範囲・選択肢・日付書式・リンク形式)は publish-worker/src/form-validate.js と同じ規則
import { COMMENT_MAX, FILES_PER_REQUEST, TEXT_INPUT_MAX } from './config.js';
import { FILE_MAX_BYTES, allowedExtensionsOf, fileAllowedBy } from './kit/files.js';
import { normalizeEmail } from './match.js';
import { asIdent, identValue } from './ident.js';

// メンバーが編集できる型(リッチエディター・計算・ユーザー選択系・システムフィールドは表示のみ)
export const EDITABLE_TYPES = new Set(['SINGLE_LINE_TEXT', 'MULTI_LINE_TEXT', 'NUMBER', 'DATE', 'TIME', 'DATETIME', 'DROP_DOWN', 'RADIO_BUTTON', 'CHECK_BOX', 'MULTI_SELECT', 'LINK', 'FILE']);
const CHOICE_TYPES = new Set(['DROP_DOWN', 'RADIO_BUTTON']);
const MULTI_TYPES = new Set(['CHECK_BOX', 'MULTI_SELECT']);
const SUMMARY_TYPES = new Set(['SINGLE_LINE_TEXT', 'MULTI_LINE_TEXT', 'NUMBER', 'CALC', 'DATE', 'TIME', 'DATETIME', 'DROP_DOWN', 'RADIO_BUTTON', 'CHECK_BOX', 'MULTI_SELECT', 'LINK', 'FILE']);
const DEFAULT_TZ = '+09:00';

export const MSG = {
  ja: { required: '必須項目です。', tooShort: (n) => `${n} 文字以上で入力してください。`, tooLong: (n) => `${n} 文字以内で入力してください。`, number: '数値で入力してください。', min: (n) => `${n} 以上で入力してください。`, max: (n) => `${n} 以下で入力してください。`, date: '日付の形式が正しくありません(例: 2026-09-08)。', time: '時刻の形式が正しくありません(例: 09:30)。', datetime: '日時の形式が正しくありません。', choice: '選択肢にない値です。', url: 'URL の形式が正しくありません(https:// または http:// で始めてください)。', mail: 'メールアドレスの形式が正しくありません。', tel: '電話番号の形式が正しくありません。', fileCount: (n) => `一度に追加できるファイルは ${n} 個までです。`, fileSize: (mb) => `1 ファイル ${mb}MB までです。`, fileExt: (list) => `添付できるファイルの形式は ${list} です。`, fileBlocked: '実行形式やスクリプトのファイルは添付できません。', rowMissing: 'この行は既に削除されています。', ownRow: '自分の行は削除できません。自分を外すと、このページに入れなくなります。社内の担当者に依頼してください。', lastRow: '最後の 1 行は削除できません。', forbidden: 'この操作は許可されていません。', config: 'この操作に必要な設定が不足しています。お問い合わせ先までご連絡ください。' },
  en: { required: 'This field is required.', tooShort: (n) => `Enter at least ${n} characters.`, tooLong: (n) => `Enter no more than ${n} characters.`, number: 'Enter a number.', min: (n) => `Enter ${n} or more.`, max: (n) => `Enter ${n} or less.`, date: 'Invalid date (e.g. 2026-09-08).', time: 'Invalid time (e.g. 09:30).', datetime: 'Invalid date and time.', choice: 'Not one of the choices.', url: 'Invalid URL (start with https:// or http://).', mail: 'Invalid email address.', tel: 'Invalid phone number.', fileCount: (n) => `Up to ${n} files can be added at once.`, fileSize: (mb) => `Each file must be ${mb}MB or smaller.`, fileExt: (list) => `Allowed file types: ${list}.`, fileBlocked: 'Executable or script files cannot be attached.', rowMissing: 'This row has already been deleted.', ownRow: 'You cannot delete your own row: you would lose access to this page. Please ask the staff.', lastRow: 'The last row cannot be deleted.', forbidden: 'This action is not allowed.', config: 'The settings required for this action are incomplete. Please contact us.' },
  zh: { required: '此项为必填。', tooShort: (n) => `请输入至少 ${n} 个字符。`, tooLong: (n) => `请输入不超过 ${n} 个字符。`, number: '请输入数字。', min: (n) => `请输入 ${n} 以上。`, max: (n) => `请输入 ${n} 以下。`, date: '日期格式不正确(例: 2026-09-08)。', time: '时间格式不正确(例: 09:30)。', datetime: '日期时间格式不正确。', choice: '不是可选的值。', url: 'URL 格式不正确(以 https:// 或 http:// 开头)。', mail: '邮箱地址格式不正确。', tel: '电话号码格式不正确。', fileCount: (n) => `一次最多添加 ${n} 个文件。`, fileSize: (mb) => `每个文件不超过 ${mb}MB。`, fileExt: (list) => `可附加的文件格式: ${list}。`, fileBlocked: '不可附加可执行文件或脚本文件。', rowMissing: '此行已被删除。', ownRow: '不能删除自己的行: 删除后将无法进入此页面。请联系负责人。', lastRow: '最后一行不能删除。', forbidden: '不允许此操作。', config: '此操作所需的设置不完整。请联系我们。' },
  'zh-TW': { required: '此欄位為必填。', tooShort: (n) => `請輸入至少 ${n} 個字元。`, tooLong: (n) => `請輸入不超過 ${n} 個字元。`, number: '請輸入數字。', min: (n) => `請輸入 ${n} 以上。`, max: (n) => `請輸入 ${n} 以下。`, date: '日期格式不正確(例: 2026-09-08)。', time: '時間格式不正確(例: 09:30)。', datetime: '日期時間格式不正確。', choice: '不是可選的值。', url: 'URL 格式不正確(以 https:// 或 http:// 開頭)。', mail: '電子郵件格式不正確。', tel: '電話號碼格式不正確。', fileCount: (n) => `一次最多新增 ${n} 個檔案。`, fileSize: (mb) => `每個檔案不超過 ${mb}MB。`, fileExt: (list) => `可附加的檔案格式: ${list}。`, fileBlocked: '不可附加可執行檔或指令碼檔案。', rowMissing: '此列已被刪除。', ownRow: '不能刪除自己的列: 刪除後將無法進入此頁面。請聯絡負責人。', lastRow: '最後一列不能刪除。', forbidden: '不允許此操作。', config: '此操作所需的設定不完整。請與我們聯絡。' },
};
export const msgFor = (lang) => MSG[lang] || MSG.ja;

// ---- 型・選択肢 ----
// ルックアップのコピー先(他のフィールドの lookup.fieldMappings が書き込む列)は API でも更新できない
export function lookupTargets(defs) {
  const out = new Set();
  const walk = (props) => {
    for (const d of Object.values(props || {})) {
      if (d && d.lookup && Array.isArray(d.lookup.fieldMappings)) for (const m of d.lookup.fieldMappings) if (m && m.field) out.add(m.field);
      if (d && d.type === 'SUBTABLE') walk(d.fields);
    }
  };
  walk(defs);
  return out;
}
export const editableDef = (def, copied) => !!def && EDITABLE_TYPES.has(def.type) && !def.lookup && !(copied && copied.has(def.code));
export const optionsOf = (def) => Object.values((def && def.options) || {}).sort((a, b) => Number(a.index) - Number(b.index)).map((o) => String(o.label));
const isBlank = (v) => v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0);
const num = (v) => (v === '' || v === null || v === undefined ? null : Number(v));

// 設定で「閲覧」と「編集」を付けた、編集できる型のフィールド(記録用のフィールドと照合に使うフィールドは除く)
export function editableFieldCodes(page, fields) {
  const s = page.settings;
  const copied = lookupTargets(fields);
  const rec = s.record || {};
  const lineField = s.line && s.line.field;
  const memberField = s.member && s.member.field;
  return Object.keys(s.fields).filter((c) => s.fields[c].view && s.fields[c].edit && editableDef(fields[c], copied) && c !== rec.updaterField && c !== rec.lastLoginField && c !== memberField && c !== lineField);
}

// ---- 値の変換と kintone 標準の検証(raw: string | string[]) ----
const toHalf = (s) => String(s).replace(/[０-９．－，：／]/g, (ch) => ({ '．': '.', '－': '-', '，': ',', '：': ':', '／': '/' })[ch] || String.fromCharCode(ch.charCodeAt(0) - 0xfee0));
const stripCtl = (s, multi) => String(s).replace(multi ? /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g : /[\x00-\x1f\x7f]/g, '');
export function coerce(def, raw, lang) {
  const M = msgFor(lang);
  const type = def.type;
  const req = def.required === true;
  if (MULTI_TYPES.has(type)) {
    const opts = optionsOf(def);
    const arr = (Array.isArray(raw) ? raw : raw === undefined || raw === null || raw === '' ? [] : [raw]).map((x) => String(x)).filter((x) => x !== '');
    if (arr.some((x) => !opts.includes(x))) return { value: arr, error: M.choice };
    const value = [...new Set(arr)];
    return { value, error: req && !value.length ? M.required : null };
  }
  let s = Array.isArray(raw) ? String(raw[0] ?? '') : raw === undefined || raw === null ? '' : String(raw);
  if (type !== 'MULTI_LINE_TEXT') s = s.replace(/\r?\n/g, ' ');
  s = stripCtl(s, type === 'MULTI_LINE_TEXT').slice(0, TEXT_INPUT_MAX + 1);
  if (CHOICE_TYPES.has(type)) {
    if (s === '') return { value: '', error: req ? M.required : null };
    return optionsOf(def).includes(s) ? { value: s, error: null } : { value: s, error: M.choice };
  }
  if (type === 'NUMBER') {
    const n = toHalf(s).trim().replace(/,/g, '');
    if (n === '') return { value: '', error: req ? M.required : null };
    if (!/^[-+]?(\d+\.?\d*|\.\d+)$/.test(n)) return { value: n, error: M.number };
    const x = Number(n);
    const lo = num(def.minValue);
    const hi = num(def.maxValue);
    if (lo !== null && Number.isFinite(lo) && x < lo) return { value: n, error: M.min(def.minValue) };
    if (hi !== null && Number.isFinite(hi) && x > hi) return { value: n, error: M.max(def.maxValue) };
    return { value: n.replace(/^\+/, ''), error: null };
  }
  if (type === 'DATE') {
    const d = toHalf(s).trim().replace(/\//g, '-');
    if (d === '') return { value: '', error: req ? M.required : null };
    const m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(d);
    if (!m) return { value: d, error: M.date };
    const iso = `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
    const dt = new Date(`${iso}T00:00:00Z`);
    return Number.isNaN(dt.getTime()) || dt.toISOString().slice(0, 10) !== iso ? { value: d, error: M.date } : { value: iso, error: null };
  }
  if (type === 'TIME') {
    const t = toHalf(s).trim();
    if (t === '') return { value: '', error: req ? M.required : null };
    const m = /^(\d{1,2}):(\d{2})(?::\d{2})?$/.exec(t);
    if (!m || Number(m[1]) > 23 || Number(m[2]) > 59) return { value: t, error: M.time };
    return { value: `${m[1].padStart(2, '0')}:${m[2]}`, error: null };
  }
  if (type === 'DATETIME') {
    const t = toHalf(s).trim().replace(/\//g, '-').replace(' ', 'T');
    if (t === '') return { value: '', error: req ? M.required : null };
    const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.exec(t);
    if (!m) return { value: t, error: M.datetime };
    const dt = new Date(`${m[1]}T${m[2]}:${m[3] || '00'}${m[4] || DEFAULT_TZ}`);
    if (Number.isNaN(dt.getTime())) return { value: t, error: M.datetime };
    return { value: dt.toISOString().replace(/\.\d{3}Z$/, 'Z'), error: null };
  }
  if (type === 'LINK') {
    const v = s.trim();
    if (v === '') return { value: '', error: req ? M.required : null };
    if (def.protocol === 'MAIL' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return { value: v, error: M.mail };
    if (def.protocol === 'CALL' && !/^[+0-9()\-\s]{3,30}$/.test(toHalf(v))) return { value: v, error: M.tel };
    if (def.protocol === 'WEB' && !/^https?:\/\/[^\s]+$/i.test(v)) return { value: v, error: M.url };
    return { value: v, error: null };
  }
  // SINGLE_LINE_TEXT / MULTI_LINE_TEXT
  if (req && s.trim() === '') return { value: s, error: M.required };
  const maxLen = num(def.maxLength);
  const minLen = num(def.minLength);
  if (maxLen !== null && maxLen > 0 && [...s].length > maxLen) return { value: s, error: M.tooLong(def.maxLength) };
  if ([...s].length > TEXT_INPUT_MAX) return { value: s, error: M.tooLong(TEXT_INPUT_MAX) };
  if (minLen !== null && minLen > 0 && s !== '' && [...s].length < minLen) return { value: s, error: M.tooShort(def.minLength) };
  return { value: s, error: null };
}

// 添付: 最新のレコードにあるファイルのうち残すもの(remove で指定した fileKey を除く)+ 追加するファイルのメタ。実体はここでは扱わない
export function planFiles(def, { existing, remove, add, rule, lang }) {
  const M = msgFor(lang);
  const rm = new Set((Array.isArray(remove) ? remove : []).map(String));
  const keep = (Array.isArray(existing) ? existing : []).filter((f) => f && f.fileKey && !rm.has(String(f.fileKey)));
  const files = (Array.isArray(add) ? add : []).filter((f) => f && typeof f === 'object' && f.name);
  if (files.length > FILES_PER_REQUEST) return { keep, add: files, error: M.fileCount(FILES_PER_REQUEST) };
  if (files.some((f) => Number(f.size) > FILE_MAX_BYTES)) return { keep, add: files, error: M.fileSize(Math.round(FILE_MAX_BYTES / 1024 / 1024)) };
  const bad = files.map((f) => fileAllowedBy(rule, f.name)).find(Boolean);
  if (bad === 'blocked') return { keep, add: files, error: M.fileBlocked };
  if (bad === 'ext') return { keep, add: files, error: M.fileExt((allowedExtensionsOf(rule) || []).join(', ')) };
  if (def.required === true && !keep.length && !files.length) return { keep, add: files, error: M.required };
  return { keep, add: files, error: null };
}

const getAll = (input, name) => {
  const v = input && input[name];
  return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
};
const rawOf = (def, input, name) => (MULTI_TYPES.has(def.type) ? getAll(input, name) : getAll(input, name)[0] ?? '');

// ---- フィールドの編集 ----
// input: { 'f.<code>': string[] , 'rm.<code>': fileKey[] } / files: { 'f.<code>': [{ name, size, type, bytes }] }
// 戻り値: { ok, values: { code: { value } }, fileOps: { code: { keep, add } }, errors: { code: message }, raw: { code: 表示用の入力値 } }
export function planFieldEdit({ page, fields, record, input, files, lang }) {
  const codes = editableFieldCodes(page, fields);
  const values = {};
  const fileOps = {};
  const errors = {};
  const raw = {};
  for (const code of codes) {
    const def = fields[code];
    if (def.type === 'FILE') {
      const existing = record[code] && Array.isArray(record[code].value) ? record[code].value : [];
      const p = planFiles(def, { existing, remove: getAll(input, `rm.${code}`), add: (files && files[`f.${code}`]) || [], rule: page.settings.attachments, lang });
      fileOps[code] = { keep: p.keep, add: p.add };
      if (p.error) errors[code] = p.error;
      continue;
    }
    const r = coerce(def, rawOf(def, input, `f.${code}`), lang);
    raw[code] = r.value;
    if (r.error) errors[code] = r.error;
    else values[code] = { value: r.value };
  }
  return { ok: Object.keys(errors).length === 0, codes, values, fileOps, errors, raw };
}

// ---- テーブルの行 ----
// ident: 本人の識別子(ident.js。メールアドレスの文字列も可)。行の作成者の列にはメールアドレスまたは LINE のユーザー ID が入る
const cell = (row, col) => String(row && row.value && row.value[col] ? row.value[col].value || '' : '').trim();
const sameId = (a, ident) => {
  const i = asIdent(ident);
  return i.kind === 'line' ? a === i.id : normalizeEmail(a) === i.id;
};
export const isOwnRow = (row, ownerColumn, ident) => !!ownerColumn && !!cell(row, ownerColumn) && sameId(cell(row, ownerColumn), ident);
// メンバー表(メンバーのメールアドレスの列があるテーブル)で、その行が自分の行か(LINE で入った人は LINE 連携 ID の列で判定)
export const isMemberOwnRow = (page, tableCode, row, ident) => {
  const m = page.settings.member;
  if (!(m && m.table && m.table === tableCode)) return false;
  const i = asIdent(ident);
  const col = i.kind === 'line' ? page.settings.line && page.settings.line.field : m.field;
  return !!col && !!cell(row, col) && sameId(cell(row, col), i);
};
// 取り消し済みの行(削除の方式が「取り消し列にチェック」で、チェック済み)。編集・削除の対象にしない
export const isCancelled = (t, row) => !!(t.deleteMode === 'cancel' && t.cancelColumn && row && row.value && row.value[t.cancelColumn] && Array.isArray(row.value[t.cancelColumn].value) && row.value[t.cancelColumn].value.length > 0);
// 行ごとにできること(§4.5.1 の 1・5)。totalRows はレコードにあるその表の全行数(見えない行を含む)
export function rowAbilities(page, tableCode, t, row, email, totalRows) {
  const own = isOwnRow(row, t.ownerColumn, email);
  const memberOwn = isMemberOwnRow(page, tableCode, row, email);
  const view = !!(t.all.view || (own && t.owner.view));
  const edit = !!(t.all.edit || (own && t.owner.edit));
  let del = !!(t.all.del || (own && t.owner.del));
  const isMemberTable = !!(page.settings.member && page.settings.member.table === tableCode);
  if (isMemberTable && (memberOwn || totalRows <= 1)) del = false;
  return { own, memberOwn, view, edit, del };
}
// 行の追加・編集で入力させる列(「閲覧」「編集」を付けた列のうち編集できる型。行の作成者・取り消しの列は除く)。
//   メンバー表では照合に使う列(メールアドレス・LINE 連携 ID)を既存の行で書き換えさせない(自分の行も他人の行も)。
//   adding: 行の追加のときだけ、メールアドレスの列を入力させる(招待。LINE 連携 ID の列は追加でも入れさせない)
export function editableColumns(page, fields, tableCode, t, { adding = false } = {}) {
  const def = fields[tableCode];
  if (!def || def.type !== 'SUBTABLE') return [];
  const copied = lookupTargets(fields);
  const m = page.settings.member;
  const lineField = page.settings.line && page.settings.line.field;
  const isMemberTable = !!(m && m.table === tableCode);
  return Object.keys(t.columns).filter((c) => t.columns[c].view && t.columns[c].edit && editableDef(def.fields[c], copied) && c !== t.ownerColumn && c !== t.cancelColumn && !(isMemberTable && (c === lineField || (c === m.field && !adding))));
}

// 1 つのテーブルへの複数の操作(画面のその場編集で「保存」を 1 回押したときの分。/rows は 1 つだけ)を、最新の行に順に当てはめる。
//   ops: [{ op: 'add' | 'edit' | 'del', rowId?, input, files }]。編集 → 追加 → 削除の順に適用(削除は行 id で行うので順序に依存しない)
//   戻り値: { ok, errors: { [i]: { col | _: message } }, tableValue, results: [{ i, op, entry(tableValue の要素。添付の書き込み先), fileOps, raw, row, comment }] }
export function planTableOps({ page, fields, record, tableCode, ops, email, lang }) {
  const M = msgFor(lang);
  const t = page.settings.tables[tableCode];
  const def = fields[tableCode];
  const errors = {};
  const results = [];
  if (!t || !def || def.type !== 'SUBTABLE') {
    ops.forEach((o, i) => { errors[i] = { _: M.forbidden }; });
    return { ok: false, errors, tableValue: [], results };
  }
  const rows = record[tableCode] && Array.isArray(record[tableCode].value) ? record[tableCode].value : [];
  const isMemberTable = !!(page.settings.member && page.settings.member.table === tableCode);
  const tableValue = rows.map((r) => ({ id: String(r.id) }));
  const byId = new Map(tableValue.map((e, i) => [String(rows[i].id), e]));
  const fillCols = (cols, existingRow, input, files, fileOps, errs, raw) => {
    const out = {};
    for (const col of cols) {
      const cdef = def.fields[col];
      if (cdef.type === 'FILE') {
        const existing = existingRow && existingRow.value && existingRow.value[col] && Array.isArray(existingRow.value[col].value) ? existingRow.value[col].value : [];
        const pf = planFiles(cdef, { existing, remove: getAll(input, `rm.${col}`), add: (files && files[`c.${col}`]) || [], rule: page.settings.attachments, lang });
        fileOps[col] = { keep: pf.keep, add: pf.add };
        if (pf.error) errs[col] = pf.error;
        continue;
      }
      const r = coerce(cdef, rawOf(cdef, input, `c.${col}`), lang);
      raw[col] = r.value;
      if (r.error) errs[col] = r.error;
      else out[col] = { value: r.value };
    }
    return out;
  };
  const order = ['edit', 'add', 'del'];
  const indexed = ops.map((o, i) => ({ ...o, i })).sort((a, b) => order.indexOf(a.op) - order.indexOf(b.op));
  // 同じ行への重複した操作は最初の 1 つだけ
  const touched = new Set();
  for (const o of indexed) {
    const errs = {};
    const fileOps = {};
    const raw = {};
    const fail = (msg) => { errors[o.i] = { _: msg }; };
    if (o.op === 'add') {
      if (!t.all.add) { fail(M.forbidden); continue; }
      const cols = editableColumns(page, fields, tableCode, t, { adding: true });
      if (!cols.length) { fail(M.config); continue; }
      const value = fillCols(cols, null, o.input, o.files, fileOps, errs, raw);
      if (t.ownerColumn && def.fields[t.ownerColumn]) value[t.ownerColumn] = { value: identValue(email) };
      const entry = { value };
      tableValue.push(entry);
      if (Object.keys(errs).length) errors[o.i] = errs;
      results.push({ i: o.i, op: 'add', entry, fileOps, raw, row: null, comment: isMemberTable ? { kind: 'member_add', cols } : null });
      continue;
    }
    const idx = rows.findIndex((r) => String(r.id) === String(o.rowId));
    if (idx < 0 || touched.has(String(o.rowId))) { fail(M.rowMissing); continue; }
    const row = rows[idx];
    const ab = rowAbilities(page, tableCode, t, row, email, rows.length);
    if (!ab.view) { fail(M.rowMissing); continue; }
    const entry = byId.get(String(row.id));
    if (o.op !== 'add' && isCancelled(t, row)) { fail(M.forbidden); continue; }
    if (o.op === 'edit') {
      if (!ab.edit) { fail(M.forbidden); continue; }
      const cols = editableColumns(page, fields, tableCode, t);
      if (!cols.length) { fail(M.config); continue; }
      entry.value = fillCols(cols, row, o.input, o.files, fileOps, errs, raw);
      touched.add(String(row.id));
      if (Object.keys(errs).length) errors[o.i] = errs;
      results.push({ i: o.i, op: 'edit', entry, fileOps, raw, row, comment: isMemberTable ? { kind: 'member_edit', cols } : null });
      continue;
    }
    if (o.op === 'del') {
      if (isMemberTable && ab.memberOwn) { fail(M.ownRow); continue; }
      if (isMemberTable && rows.length - indexed.filter((x) => x.op === 'del' && x.i !== o.i && !errors[x.i]).length <= 1) { fail(M.lastRow); continue; }
      if (!ab.del) { fail(M.forbidden); continue; }
      touched.add(String(row.id));
      if (t.deleteMode === 'cancel') {
        const cdef = t.cancelColumn && def.fields[t.cancelColumn];
        const opts = cdef && cdef.type === 'CHECK_BOX' ? optionsOf(cdef) : [];
        if (!opts.length) { fail(M.config); continue; }
        entry.value = { [t.cancelColumn]: { value: [opts[0]] } };
      } else {
        const at = tableValue.indexOf(entry);
        if (at >= 0) tableValue.splice(at, 1);
      }
      results.push({ i: o.i, op: 'del', entry: null, fileOps, raw, row, comment: { kind: isMemberTable ? 'member_del' : 'del', cols: Object.keys(t.columns) } });
      continue;
    }
    fail(M.forbidden);
  }
  return { ok: Object.keys(errors).length === 0, errors, tableValue, results };
}

// ---- 操作の記録(レコードのコメント。§4.5.1 の 7)----
// 行の内容の要約(文字・数値・選択肢の列。添付はファイル名だけ)。見せている列(columns に閲覧がある)だけ
export function summarizeRow(tableDef, t, row, cols) {
  const parts = [];
  for (const col of cols || Object.keys(t.columns)) {
    const cdef = tableDef.fields[col];
    const cell = row && row.value && row.value[col];
    if (!cdef || !cell || !SUMMARY_TYPES.has(cdef.type) || !(t.columns[col] && t.columns[col].view)) continue;
    const v = cell.value;
    let s = '';
    if (cdef.type === 'FILE') s = (Array.isArray(v) ? v : []).map((f) => f && f.name).filter(Boolean).join(', ');
    else if (Array.isArray(v)) s = v.join(', ');
    else s = v == null ? '' : String(v);
    s = s.replace(/\s+/g, ' ').trim();
    if (s) parts.push(`${cdef.label || col}: ${s.slice(0, 120)}`);
  }
  return parts.join(' / ');
}
const COMMENT_TEXT = {
  ja: { del: (e, t) => `マイページから ${e} が「${t}」の行を削除しました`, member_del: (e, t) => `マイページから ${e} が「${t}」のメンバーの行を削除しました`, member_add: (e, t) => `マイページから ${e} が「${t}」にメンバーの行を追加しました`, member_edit: (e, t) => `マイページから ${e} が「${t}」のメンバーの行を変更しました`, prefix: '[KINTAUROS マイページ] ' },
  en: { del: (e, t) => `${e} deleted a row of "${t}" from My Page`, member_del: (e, t) => `${e} deleted a member row of "${t}" from My Page`, member_add: (e, t) => `${e} added a member row to "${t}" from My Page`, member_edit: (e, t) => `${e} changed a member row of "${t}" from My Page`, prefix: '[KINTAUROS My Page] ' },
  zh: { del: (e, t) => `${e} 通过我的页面删除了「${t}」的一行`, member_del: (e, t) => `${e} 通过我的页面删除了「${t}」的会员行`, member_add: (e, t) => `${e} 通过我的页面在「${t}」添加了会员行`, member_edit: (e, t) => `${e} 通过我的页面更改了「${t}」的会员行`, prefix: '[KINTAUROS 我的页面] ' },
  'zh-TW': { del: (e, t) => `${e} 透過我的頁面刪除了「${t}」的一列`, member_del: (e, t) => `${e} 透過我的頁面刪除了「${t}」的會員列`, member_add: (e, t) => `${e} 透過我的頁面在「${t}」新增了會員列`, member_edit: (e, t) => `${e} 透過我的頁面變更了「${t}」的會員列`, prefix: '[KINTAUROS 我的頁面] ' },
};
export function commentText(lang, { kind, email, tableLabel, summary }) {
  const C = COMMENT_TEXT[lang] || COMMENT_TEXT.ja;
  const i = asIdent(email);
  const head = (C[kind] || C.del)(i.kind === 'line' ? `LINE ${i.name ? `${i.name} (${i.id})` : i.id}` : i.id, tableLabel);
  return `${C.prefix}${head}${summary ? `: ${summary}` : ''}`.slice(0, COMMENT_MAX);
}

// ---- 自己登録(§19)----
// 入力させるフィールド(添付は不可)+ 固定値 + 本人確認した識別子で、POST record の本文を作る。戻り値: { ok, errors: { code: msg }, record, raw }
export function signupFieldCodes(page, fields) {
  const copied = lookupTargets(fields);
  const s = page.settings;
  return (s.signup.fields || []).filter((c) => fields[c] && editableDef(fields[c], copied) && fields[c].type !== 'FILE' && c !== s.member.field && c !== (s.line && s.line.field));
}
export function planSignup({ page, fields, input, ident, lang }) {
  const M = msgFor(lang);
  const s = page.settings;
  const i = asIdent(ident);
  const record = {};
  const errors = {};
  const raw = {};
  // 固定値(契約者の設定)。照合に使うフィールドには入れない(本人の識別子だけを下で入れる)
  for (const d of s.signup.defaults || []) if (fields[d.field] && !s.signup.fields.includes(d.field) && d.field !== s.member.field && d.field !== (s.line && s.line.field)) record[d.field] = { value: MULTI_TYPES.has(fields[d.field].type) ? d.value.split(',').map((x) => x.trim()).filter(Boolean) : d.value };
  for (const code of signupFieldCodes(page, fields)) {
    const r = coerce(fields[code], rawOf(fields[code], input, `f.${code}`), lang);
    raw[code] = r.value;
    if (r.error) errors[code] = r.error;
    else record[code] = { value: r.value };
  }
  if (i.kind === 'line') {
    if (!(s.line && s.line.field && fields[s.line.field])) return { ok: false, errors: { _: M.config }, record: {}, raw };
    record[s.line.field] = { value: i.id };
  } else {
    if (!fields[s.member.field]) return { ok: false, errors: { _: M.config }, record: {}, raw };
    record[s.member.field] = { value: i.id };
  }
  return { ok: Object.keys(errors).length === 0, errors, record, raw };
}
