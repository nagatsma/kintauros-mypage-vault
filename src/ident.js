// 本人の識別子(mypage-worker の ident.js と同じ)。メールアドレス('email')か LINE のユーザー ID('line')のどちらか 1 つ。
//   { kind: 'email' | 'line', id, name? }。id は email なら小文字・空白除去、line なら LINE の sub そのまま(大文字小文字を区別)
import { hmacHex, normalizeEmail } from './crypto.js';

export const asIdent = (x) => {
  if (x && typeof x === 'object' && x.kind) return x.kind === 'line' ? { kind: 'line', id: String(x.id || ''), name: x.name ? String(x.name).slice(0, 80) : '' } : { kind: 'email', id: normalizeEmail(x.id) };
  return { kind: 'email', id: normalizeEmail(x) };
};
export const isLine = (ident) => !!ident && ident.kind === 'line';
// 画面用の表示: メールアドレス、または「LINE: 表示名」
export const identLabel = (ident) => {
  const i = asIdent(ident);
  return i.kind === 'line' ? `LINE: ${i.name || i.id}` : i.id;
};
// レート制限・MAU・ログ用のハッシュ(email は `email:` 接頭辞。画面側と同じ形)
export const identHash = (env, ident) => {
  const i = asIdent(ident);
  return hmacHex(env, `${i.kind === 'line' ? 'line:' : 'email:'}${i.id}`);
};
