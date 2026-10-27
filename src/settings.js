// サイト・ページの設定の検証(純関数。プラグインの config-schema.json と同じ形)。設計 §4.7 / §4.5.1
// 不正な値は落として既定に戻す(保存を止めるのは errors に入れたものだけ)
import {
  CONDITION_MAX, CONTACT_MAX, LIST_FIELDS_MAX, PAGE_DAILY_LIMIT_DEFAULT, PAGE_DAILY_LIMIT_MAX, PAGE_NAME_MAX, SESSION_DAYS_DEFAULT, SESSION_DAYS_MAX, SESSION_DAYS_MIN,
  SITE_NAME_MAX, THEME_COLOR_DEFAULT, THEME_COLOR_RE, URL_MAX, LINE_LINK_DAYS_DEFAULT, LINE_LINK_DAYS_MAX, LINE_LINK_DAYS_MIN, SIGNUP_CONSENT_MAX, SIGNUP_FIELDS_MAX,
} from './config.js';
import { normalizeAttachmentRule } from './kit/files.js';
import { isEmail } from './match.js';

const CODE_RE = /^[^\s\x00-\x1f\x7f"]{1,128}$/;
const HTTPS_RE = /^https:\/\/[^\s"'<>]+$/;
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max).trim() : '');
const bool = (v, d = false) => (typeof v === 'boolean' ? v : d);
const code = (v) => (typeof v === 'string' && CODE_RE.test(v) ? v : '');
const codeList = (v, max) => (Array.isArray(v) ? v.map(code).filter(Boolean).filter((c, i, a) => a.indexOf(c) === i).slice(0, max) : []);
const idList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && /^[0-9a-f-]{36}$/.test(x)).slice(0, 200) : []);

export function validateSiteSettings(input) {
  const s = input && typeof input === 'object' ? input : {};
  const errors = [];
  const login = s.login && typeof s.login === 'object' ? s.login : {};
  const line = s.line && typeof s.line === 'object' ? s.line : {};
  const card = s.card && typeof s.card === 'object' ? s.card : {};
  const out = {
    name: str(s.name, SITE_NAME_MAX),
    themeColor: typeof s.themeColor === 'string' && THEME_COLOR_RE.test(s.themeColor) ? s.themeColor.toLowerCase() : THEME_COLOR_DEFAULT,
    contact: str(s.contact, CONTACT_MAX),
    privacyUrl: str(s.privacyUrl, URL_MAX),
    // 管理者の通知先(任意。量の上限を超えたときの通知。alert.js)。メンバーの画面(/v1/site)には返さない
    notifyEmail: str(s.notifyEmail, 254).toLowerCase(),
    login: { google: bool(login.google, true), email: bool(login.email, true) },
    sessionDays: Number.isInteger(s.sessionDays) && s.sessionDays >= SESSION_DAYS_MIN && s.sessionDays <= SESSION_DAYS_MAX ? s.sessionDays : SESSION_DAYS_DEFAULT,
    topCheckScope: s.topCheckScope === 'pages' ? 'pages' : 'all',
    topCheckPages: idList(s.topCheckPages),
    pageOrder: idList(s.pageOrder),
    lang: ['ja', 'en', 'zh', 'zh-TW'].includes(s.lang) ? s.lang : 'ja',
    // LINE ログイン(§4.2.10)。チャネル ID とシークレットは settings でなく sites の列(api.js putSite)
    line: {
      enabled: bool(line.enabled),
      linkDays: Number.isInteger(line.linkDays) && line.linkDays >= LINE_LINK_DAYS_MIN && line.linkDays <= LINE_LINK_DAYS_MAX ? line.linkDays : LINE_LINK_DAYS_DEFAULT,
      selfLink: bool(line.selfLink, true),
    },
    // メンバー証(QR。設計 §18。2026-09-27 にドメイン単位へ): 対象のアプリ(ページ)は 1 つ。フィールドがそのページで閲覧できるかは cardForPage で見る(api.js putSite / member.js)
    card: { enabled: bool(card.enabled), page: typeof card.page === 'string' && /^[0-9a-f-]{36}$/.test(card.page) ? card.page : '', field: code(card.field), fields: codeList(card.fields, LIST_FIELDS_MAX), name: str(card.name, PAGE_NAME_MAX) },
  };
  if (out.privacyUrl && !HTTPS_RE.test(out.privacyUrl)) errors.push({ path: 'privacyUrl', message: 'https:// で始まる URL を指定してください' });
  if (out.notifyEmail && !isEmail(out.notifyEmail)) errors.push({ path: 'notifyEmail', message: 'メールアドレスの形式で入力してください' });
  if (!out.login.google && !out.login.email) errors.push({ path: 'login', message: 'ログイン方法を 1 つ以上選んでください' });
  return { ok: errors.length === 0, value: out, errors };
}

// フィールド・テーブルのアクセス権(§4.5.1)。編集/削除をオンにすると閲覧も自動でオン。閲覧を外すと編集・削除も外れる
const fieldAccess = (a) => {
  const edit = bool(a && a.edit);
  const view = bool(a && a.view) || edit;
  return { view, edit };
};
const rowAccess = (a, withAdd) => {
  const edit = bool(a && a.edit);
  const del = bool(a && a.del);
  const view = bool(a && a.view) || edit || del;
  const out = { view, edit, del };
  if (withAdd) out.add = bool(a && a.add);
  return out;
};

export function validatePageSettings(input) {
  const s = input && typeof input === 'object' ? input : {};
  const errors = [];
  const member = s.member && typeof s.member === 'object' ? s.member : {};
  const list = s.list && typeof s.list === 'object' ? s.list : {};
  const sort = list.sort && typeof list.sort === 'object' ? list.sort : {};
  const record = s.record && typeof s.record === 'object' ? s.record : {};
  const line = s.line && typeof s.line === 'object' ? s.line : {};
  const signup = s.signup && typeof s.signup === 'object' ? s.signup : {};
  const fields = {};
  if (s.fields && typeof s.fields === 'object') {
    for (const [c, a] of Object.entries(s.fields)) {
      if (!code(c)) continue;
      const acc = fieldAccess(a);
      if (acc.view) fields[c] = acc;
    }
  }
  const tables = {};
  if (s.tables && typeof s.tables === 'object') {
    for (const [c, t] of Object.entries(s.tables)) {
      if (!code(c) || !t || typeof t !== 'object') continue;
      const all = rowAccess(t.all, true);
      const owner = rowAccess(t.owner, false);
      // 「すべての行」で許したものは「行の作成者」でも自動でオン
      owner.view = owner.view || all.view;
      owner.edit = owner.edit || all.edit;
      owner.del = owner.del || all.del;
      const columns = {};
      if (t.columns && typeof t.columns === 'object') {
        for (const [cc, a] of Object.entries(t.columns)) {
          if (!code(cc)) continue;
          const acc = fieldAccess(a);
          if (acc.view) columns[cc] = acc;
        }
      }
      const ownerColumn = code(t.ownerColumn);
      if (!ownerColumn) {
        // 列を指定しないと「行の作成者」の行は選べない
        owner.view = all.view;
        owner.edit = all.edit;
        owner.del = all.del;
      }
      if (!all.view && !all.add && !owner.view) continue; // 何も許していないテーブルは持たない
      const editable = Object.values(columns).some((a) => a.edit);
      if ((all.add || all.edit || owner.edit) && !editable) errors.push({ path: `tables.${c}`, message: '入力できる列を 1 つ以上選んでください' });
      tables[c] = { all, owner, ownerColumn, deleteMode: t.deleteMode === 'cancel' ? 'cancel' : 'remove', cancelColumn: code(t.cancelColumn), columns };
    }
  }
  const out = {
    name: str(s.name, PAGE_NAME_MAX),
    enabled: bool(s.enabled),
    member: { field: code(member.field), table: code(member.table) },
    condition: str(s.condition, CONDITION_MAX),
    fields,
    tables,
    list: {
      fields: codeList(list.fields, LIST_FIELDS_MAX),
      sort: { field: code(sort.field), order: sort.order === 'asc' ? 'asc' : 'desc' },
      search: codeList(list.search, LIST_FIELDS_MAX),
    },
    checkScope: s.checkScope === 'pages' ? 'pages' : 'all',
    checkPages: idList(s.checkPages),
    record: { updaterField: code(record.updaterField), lastLoginField: code(record.lastLoginField) },
    // メンバーがアップロードできるファイルの形式(§4.5。Webフォーム公開と同じ規則: 既定は画像・実行形式は常に拒否)
    attachments: normalizeAttachmentRule(s.attachments),
    // LINE 連携 ID のフィールド(§4.2.10。メンバー表を使うページではその表の列のコード)
    line: { field: code(line.field) },
    // メンバーの自己登録(§19): 本人確認した人がレコードを持っていなければ、その場で自分のレコードを作れる。追加専用の第 2 トークンが要る
    signup: {
      enabled: bool(signup.enabled),
      fields: codeList(signup.fields, SIGNUP_FIELDS_MAX),
      defaults: (Array.isArray(signup.defaults) ? signup.defaults : []).map((d) => ({ field: code(d && d.field), value: typeof (d && d.value) === 'string' ? d.value.slice(0, 1000) : '' })).filter((d) => d.field).slice(0, SIGNUP_FIELDS_MAX),
      consent: str(signup.consent, SIGNUP_CONSENT_MAX),
    },
    dailyLimit: Number.isInteger(s.dailyLimit) && s.dailyLimit >= 100 && s.dailyLimit <= PAGE_DAILY_LIMIT_MAX ? s.dailyLimit : PAGE_DAILY_LIMIT_DEFAULT,
  };
  // 一覧に出せるのは「閲覧」を付けたフィールドだけ(外したら自動で外れる)
  out.list.fields = out.list.fields.filter((c) => fields[c] && fields[c].view);
  out.list.search = out.list.search.filter((c) => fields[c] && fields[c].view);
  if (out.signup.enabled && out.member.table) errors.push({ path: 'signup', message: '自己登録は、メンバーのメールアドレスがテーブルの列ではないアプリでだけ使えます' });
  if (out.enabled) {
    if (!out.member.field) errors.push({ path: 'member.field', message: 'メンバーのメールアドレスのフィールドを選んでください' });
    if (!out.name) errors.push({ path: 'name', message: 'ページ名を入力してください' });
  }
  return { ok: errors.length === 0, value: out, errors };
}

// メンバー証の設定をページに当てる(純関数): 対象がこのページで、QR のフィールドに閲覧が付いていれば { field, fields(閲覧できるものだけ), name }。そうでなければ null
//   card は site.settings.card。ページの設定(閲覧)を外したら自動で使えなくなる(保存は止めない)
export function cardForPage(card, page) {
  if (!card || !card.enabled || !page || card.page !== page.id) return null;
  const fields = (page.settings && page.settings.fields) || {};
  if (!(card.field && fields[card.field] && fields[card.field].view)) return null;
  return { field: card.field, fields: (card.fields || []).filter((c) => c !== card.field && fields[c] && fields[c].view), name: card.name || '' };
}

// 取得に使うフィールド(表示・照合に必要なものだけ。§4.4)。site を渡すとメンバー証のフィールドも含める
export function requestedFields(page, site = null) {
  const s = page.settings;
  const set = new Set(['$id', '$revision']);
  if (s.member.table) set.add(s.member.table);
  else if (s.member.field) set.add(s.member.field);
  if (s.line && s.line.field && !s.member.table) set.add(s.line.field);
  for (const c of Object.keys(s.fields)) set.add(c);
  for (const c of Object.keys(s.tables)) set.add(c);
  for (const c of s.list.fields) set.add(c);
  const card = site ? cardForPage(site.settings && site.settings.card, page) : null;
  if (card) { set.add(card.field); for (const c of card.fields) set.add(c); }
  return [...set];
}
