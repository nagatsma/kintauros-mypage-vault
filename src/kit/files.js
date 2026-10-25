// 複製元: kintauros-plugins の packages/worker-kit/src/files.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
// 添付ファイルの受け付け規則(publish-worker の Webフォーム公開と mypage-worker のメンバーのアップロードで共用)。
//   SERVICE-POLICY §4-3 の例外: 契約者が「指定した拡張子のみ(既定は画像)」か「実行形式を除く任意」を選ぶ。実行形式は常に拒否。
//   判定はファイル名の最後のドット以降(小文字)だけで行い、内容の検査・ウイルス検査は行わない(設定画面と利用特約に明記)
export const FILE_DEFAULT_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'heic'];
export const FILE_BLOCKED_EXTS = new Set(['exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'pif', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'lnk', 'dll', 'cpl', 'jar', 'reg', 'sh', 'app', 'dmg']);
export const FILE_EXT_RE = /^[a-z0-9]{1,10}$/;
export const FILE_EXTS_MAX = 50;
export const FILE_MAX_BYTES = 10 * 1024 * 1024; // 1 ファイル 10MB(方針 §4-3)

export const fileExtension = (name) => {
  const s = String(name || '');
  const i = s.lastIndexOf('.');
  return i > 0 && i < s.length - 1 ? s.slice(i + 1).toLowerCase() : '';
};

/** 拡張子の入力(配列 / カンマ・空白区切りの文字列)→ 小文字・先頭のドット除去・重複除去・実行形式除外 */
export function normalizeExtensions(input) {
  const src = Array.isArray(input) ? input : typeof input === 'string' ? input.split(/[,\s、，]+/) : [];
  const out = [];
  for (const raw of src) {
    const x = String(raw || '').trim().toLowerCase().replace(/^[.\s]+/, '');
    if (!x || !FILE_EXT_RE.test(x) || FILE_BLOCKED_EXTS.has(x) || out.includes(x)) continue;
    out.push(x);
    if (out.length >= FILE_EXTS_MAX) break;
  }
  return out;
}

/** 受け付け規則の正規化: { mode: 'list' | 'any', extensions } */
export function normalizeAttachmentRule(input) {
  const o = input && typeof input === 'object' ? input : {};
  const mode = o.mode === 'any' ? 'any' : 'list';
  const extensions = mode === 'list' ? normalizeExtensions(o.extensions) : [];
  return { mode, extensions: mode === 'list' && !extensions.length ? [...FILE_DEFAULT_EXTS] : extensions };
}

/** 規則が受け付ける拡張子の一覧(null = 実行形式を除く任意) */
export const allowedExtensionsOf = (rule) => {
  if (rule && rule.mode === 'any') return null;
  return rule && Array.isArray(rule.extensions) && rule.extensions.length ? rule.extensions : FILE_DEFAULT_EXTS;
};

/** ファイル名の拡張子で判定: '' = 可 / 'blocked' = 実行形式 / 'ext' = 許可リスト外 */
export function fileAllowedBy(rule, name) {
  const ext = fileExtension(name);
  if (FILE_BLOCKED_EXTS.has(ext)) return 'blocked';
  const list = allowedExtensionsOf(rule);
  return list && !list.includes(ext) ? 'ext' : '';
}
