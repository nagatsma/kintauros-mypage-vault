-- P2: メンバーの本人確認とセッションを保管庫へ(VAULT 設計 §5)。
--   codes の kind に 'oauth'(Google / LINE の state。PKCE の verifier・nonce・ブラウザとの結び付けのハッシュを data に。10 分・1 回限り)が加わる
--   revoked_sessions: ログアウトしたセッション(sid の SHA-256)。セッションは延長しても sid が変わらないので、延長した写しもまとめて無効になる。
--                     期限はセッションの最長の有効期間より長くし、日次の掃除で消す。アドレス・レコードは入れない
CREATE TABLE revoked_sessions (
  sid_hash TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_revoked_sessions_expires ON revoked_sessions(expires_at);
CREATE INDEX idx_revoked_sessions_site ON revoked_sessions(site_id);
