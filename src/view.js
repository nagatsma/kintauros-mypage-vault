// 取得したレコードを、契約者が選んだフィールド・テーブル・列だけに絞る(VAULT 設計 §6.2-2。mypage-worker の view.js を移したもの。純関数)。
// kintone のアクセス権は API トークンでは効かない(MYPAGE 設計 §2.4 K1)ので、見せる範囲を決めるのはここだけ。
// 画面側へ返す前に必ず通し、通していない値を応答に出さない
import { editableColumns, editableFieldCodes, isCancelled, rowAbilities } from './edit.js';

const SYSTEM = new Set(['RECORD_NUMBER', 'CREATED_TIME', 'UPDATED_TIME', 'CREATOR', 'MODIFIER', 'STATUS', 'STATUS_ASSIGNEE', 'CATEGORY']);
// 一覧に出せる型(テーブル・添付・リッチエディターは除く)
export const LISTABLE_TYPES = new Set(['SINGLE_LINE_TEXT', 'NUMBER', 'CALC', 'DATE', 'TIME', 'DATETIME', 'DROP_DOWN', 'RADIO_BUTTON', 'CHECK_BOX', 'MULTI_SELECT', 'LINK', 'RECORD_NUMBER', 'CREATED_TIME', 'UPDATED_TIME', 'CREATOR', 'MODIFIER', 'USER_SELECT', 'ORGANIZATION_SELECT', 'GROUP_SELECT', 'STATUS', 'CATEGORY']);

// 戻り値: { id, revision, canEdit(編集できるフィールドがある), values: { code: { type, value } },
//          tables: { code: { rows: [{ id, own, canEdit, canDel, cancelled, values: { col: { type, value } } }], canAdd, canEdit, canDel } } }
export function viewRecord(page, fields, record, email) {
  const s = page.settings;
  const out = { id: String((record.$id && record.$id.value) || ''), revision: String((record.$revision && record.$revision.value) || ''), canEdit: editableFieldCodes(page, fields).length > 0, values: {}, tables: {} };
  for (const [code, acc] of Object.entries(s.fields)) {
    if (!acc.view) continue;
    const def = fields[code];
    const v = record[code];
    if (!def || !v || def.type === 'SUBTABLE') continue;
    out.values[code] = { type: def.type, value: v.value };
  }
  for (const [code, t] of Object.entries(s.tables)) {
    const def = fields[code];
    const v = record[code];
    if (!def || def.type !== 'SUBTABLE' || !v || !Array.isArray(v.value)) continue;
    const cols = def.fields || {};
    const rows = [];
    for (const row of v.value) {
      const ab = rowAbilities(page, code, t, row, email, v.value.length);
      if (!ab.view) continue;
      const values = {};
      for (const [col, acc] of Object.entries(t.columns)) {
        if (!acc.view || !cols[col] || !row.value || !row.value[col]) continue;
        values[col] = { type: cols[col].type, value: row.value[col].value };
      }
      const cancelled = isCancelled(t, row);
      // 編集は入力できる列があるときだけ。取り消し済みの行は編集・削除の対象にしない
      const canEdit = ab.edit && !cancelled && editableColumns(page, fields, code, t).length > 0;
      rows.push({ id: String(row.id || ''), own: ab.own, memberOwn: ab.memberOwn, canEdit, canDel: ab.del && !cancelled, cancelled: !!cancelled, values });
    }
    const canAdd = !!t.all.add && editableColumns(page, fields, code, t, { adding: true }).length > 0;
    out.tables[code] = { rows, canAdd, canEdit: rows.some((r) => r.canEdit), canDel: rows.some((r) => r.canDel) };
  }
  return out;
}

// 一覧の 1 行(設定した一覧のフィールドの値だけ)。先頭が見出し
export function listRow(page, fields, shaped) {
  const cells = page.settings.list.fields.map((code) => {
    const def = fields[code];
    const v = shaped.values[code];
    return { code, label: def ? def.label || code : code, type: def ? def.type : '', value: v ? v.value : null };
  });
  return { id: shaped.id, cells };
}

// 一覧に出せるフィールドの候補(設定画面と同じ規則)
export const listableFields = (page, fields) => Object.keys(page.settings.fields).filter((c) => page.settings.fields[c].view && fields[c] && LISTABLE_TYPES.has(fields[c].type));

export const isSystemType = (t) => SYSTEM.has(t);
