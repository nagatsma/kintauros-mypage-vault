// 本人とレコードの照合(設計 §4.3。純関数)。
//   `=`/`in` は大文字小文字を区別するので `like` を併用し(登録直後の索引の遅れは `=` 側で補う)、取得後に Worker で再照合する。
//   クエリの組み立ては Worker だけが行い、メンバーの入力(アドレス・検索語)は必ずエスケープする
import { LIST_MAX_OFFSET, LIST_PAGE_SIZE, SEARCH_KEYWORD_MAX } from './config.js';

export const normalizeEmail = (s) => String(s || '').trim().toLowerCase();
export const EMAIL_RE = /^[^\s@"\\]+@[^\s@"\\]+\.[^\s@"\\]+$/;
export const isEmail = (s) => typeof s === 'string' && s.length <= 254 && EMAIL_RE.test(s);

// kintone のクエリ文字列リテラル(" と \ をエスケープ)
export const qstr = (v) => `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

// メンバーのメールアドレスの条件(通常のフィールド / テーブルの列)
export function memberCondition(member, email) {
  const e = normalizeEmail(email);
  const f = member.field;
  if (member.table) return `(${f} in (${qstr(e)}) or ${f} like ${qstr(e)})`;
  return `(${f} = ${qstr(e)} or ${f} like ${qstr(e)})`;
}
// LINE 連携 ID の条件(§4.2.10。メンバー表を使うページではその表の列)。LINE のユーザー ID は大文字小文字を区別するので = / in だけ
export function lineCondition(page, lineId) {
  const s = page.settings;
  const f = s.line && s.line.field;
  if (!f) return null;
  if (s.member.table) return `${f} in (${qstr(lineId)})`;
  return `${f} = ${qstr(lineId)}`;
}
// 本人の識別子(ident.js の { kind, id }、または従来どおりメールアドレスの文字列)から照合の条件を作る。LINE で入れないページは null
const identOf = (x) => (x && typeof x === 'object' && x.kind ? x : { kind: 'email', id: normalizeEmail(x) });
export function identCondition(page, ident) {
  const i = identOf(ident);
  return i.kind === 'line' ? lineCondition(page, i.id) : memberCondition(page.settings.member, i.id);
}
export const pageAcceptsIdent = (page, ident) => identCondition(page, ident) !== null;

// 契約者の「対象にする条件」は kintone のクエリ文字列をそのまま and でつなぐ。order by / limit / offset を含んでいたら落とす
export function sanitizeCondition(condition) {
  const c = String(condition || '').trim();
  if (!c) return '';
  if (/\b(order\s+by|limit|offset)\b/i.test(c)) return '';
  return c;
}

export function keywordCondition(fields, keyword) {
  const kw = String(keyword || '').trim().slice(0, SEARCH_KEYWORD_MAX);
  if (!kw || !fields.length) return '';
  return `(${fields.map((f) => `${f} like ${qstr(kw)}`).join(' or ')})`;
}

// 一覧のクエリ: メンバーの条件 and 対象にする条件 [and 検索] order by … limit 20 offset N
export function listQuery(page, ident, { keyword = '', offset = 0, fieldTypes = {} } = {}) {
  const s = page.settings;
  const parts = [identCondition(page, ident)];
  const cond = sanitizeCondition(s.condition);
  if (cond) parts.push(`(${cond})`);
  const kw = keywordCondition(s.list.search, keyword);
  if (kw) parts.push(kw);
  const sortField = s.list.sort.field && fieldTypes[s.list.sort.field] !== 'RECORD_NUMBER' ? s.list.sort.field : '$id';
  const off = Math.min(Math.max(0, Math.floor(Number(offset) || 0)), LIST_MAX_OFFSET);
  return `${parts.join(' and ')} order by ${sortField} ${s.list.sort.order === 'asc' ? 'asc' : 'desc'} limit ${LIST_PAGE_SIZE + 1} offset ${off}`;
}

// 詳細(1 件)のクエリ: URL のレコード番号だけでは開けない(IDOR 防止)
export function recordQuery(page, ident, recordId) {
  const s = page.settings;
  const parts = [`$id = ${Number(recordId)}`, identCondition(page, ident)];
  const cond = sanitizeCondition(s.condition);
  if (cond) parts.push(`(${cond})`);
  return `${parts.join(' and ')} limit 1`;
}

// 「あわせて確認するページ」用: 1 件あるかだけ(取得列は $id)
export function membershipQuery(page, ident) {
  const s = page.settings;
  const parts = [identCondition(page, ident)];
  const cond = sanitizeCondition(s.condition);
  if (cond) parts.push(`(${cond})`);
  return `${parts.join(' and ')} limit 1`;
}

// Worker 側の再照合: like は単語の一致なので、取得したレコードのアドレスが完全一致するものだけを残す。
//   member: ページ設定の member({ field, table })。ident が LINE のときは呼び出し側が { field: LINE 連携 ID の列, table } を渡す(matchSpec)
export function recordMatches(record, member, ident) {
  const i = identOf(ident);
  const norm = i.kind === 'line' ? (v) => String(v || '').trim() : normalizeEmail;
  const e = norm(i.id);
  if (!e) return false;
  if (member.table) {
    const t = record[member.table];
    const rows = t && Array.isArray(t.value) ? t.value : [];
    return rows.some((row) => {
      const cell = row && row.value && row.value[member.field];
      return cell && norm(cell.value) === e;
    });
  }
  const f = record[member.field];
  return !!f && norm(f.value) === e;
}
export const filterMatches = (records, member, ident) => records.filter((r) => recordMatches(r, member, ident));
// 識別子の種類に応じた照合の対象({ field, table })。LINE は LINE 連携 ID のフィールド(メンバー表ならその列)
export function matchSpec(page, ident) {
  const s = page.settings;
  if (identOf(ident).kind === 'line') return s.line && s.line.field ? { field: s.line.field, table: s.member.table } : null;
  return s.member;
}
export const identMatches = (records, page, ident) => {
  const spec = matchSpec(page, ident);
  return spec ? filterMatches(records, spec, ident) : [];
};
