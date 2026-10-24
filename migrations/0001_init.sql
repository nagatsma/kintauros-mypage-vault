-- 保管庫の初期スキーマ。mypage-worker の 0001_init・0002_line・0003_signup をまとめたもの(保管庫は新しい D1 で始める。
-- 既存のトークンは移さず、プラグインから登録し直す。VAULT 設計 §11)
-- 不変条件: レコードの内容・添付ファイルをこの DB に置かない。メンバーの台帳を作らない(アドレスは HMAC でしか残さない)。
--           API トークンは DEK で暗号化してしか置かず、API 応答に返さない。

-- サイト = 契約の単位(kintone ドメイン 1 つ)。URL・ログイン方法・有効期間はサイトに 1 つ
CREATE TABLE sites (
  id TEXT PRIMARY KEY,                    -- UUID
  slug TEXT NOT NULL UNIQUE,              -- {slug}.kintauros.me
  domain TEXT NOT NULL UNIQUE,            -- 顧客の kintone ドメイン(正規化済み)。1 ドメイン = 1 サイト
  settings TEXT NOT NULL,                 -- JSON(name / themeColor / contact / privacyUrl / login / sessionDays / topCheckScope / topCheckPages / pageOrder)
  session_epoch INTEGER NOT NULL DEFAULT 1, -- 一斉ログアウトで +1(それより前の Cookie は無効)
  custom_host TEXT,                       -- 独自ドメイン(M3)
  host_status TEXT,
  cf_hostname_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'stopped' | 'suspended'
  purge_after TEXT,                       -- ライセンス失効後の完全削除予定
  license_status TEXT,
  license_plan TEXT,
  license_expires_at TEXT,
  license_checked_at TEXT,
  settings_updated_by TEXT,               -- 最後にサイト全体の設定を変えたページ ID(設定画面に「最後に変更した人・日時」を出す)
  settings_updated_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_sites_custom_host ON sites(custom_host);

-- ページ = マイページを有効にした kintone アプリ 1 つ
CREATE TABLE pages (
  id TEXT PRIMARY KEY,                    -- UUID
  site_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  slug TEXT NOT NULL,                     -- /{slug}/(サイト内で一意)
  key_hash TEXT NOT NULL,                 -- ページ鍵(プラグイン API 認証)の SHA-256。鍵本体は保存しない
  settings TEXT NOT NULL,                 -- JSON(name / enabled / member / condition / fields / tables / list / checkScope / checkPages / record / dailyLimit)
  dek_wrapped TEXT NOT NULL,              -- ページ DEK を VAULT_KEK で包んだもの
  token_enc TEXT,                         -- 閲覧+編集の API トークン(DEK で暗号化)。API 応答には返さない
  token_last4 TEXT,
  token_verified_at TEXT,                 -- 権限(閲覧+編集だけ)を検証した日時。毎日再検証する
  token_error TEXT,                       -- 再検証で見つかった問題(権限が広がった等)。あれば利用を止める
  status TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'stopped'
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (site_id, slug),
  UNIQUE (site_id, app_id)
);
CREATE INDEX idx_pages_site ON pages(site_id);

-- フィールド定義・レイアウトのキャッシュ(個人情報を含まない。5 分)
CREATE TABLE form_cache (
  page_id TEXT PRIMARY KEY,
  fields TEXT NOT NULL,
  layout TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);

-- 一時データ: 確認コード(ハッシュ)・受け渡しコード。使えば削除、期限で削除
CREATE TABLE codes (
  id TEXT PRIMARY KEY,                    -- 乱数(URL に出す識別子。コード本体ではない)
  site_id TEXT NOT NULL,
  kind TEXT NOT NULL,                     -- 'email' | 'handoff'
  hash TEXT NOT NULL,                     -- コード本体の HMAC
  data TEXT NOT NULL,                     -- JSON(email / method / host / next / pages)。期限で消す
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_codes_expires ON codes(expires_at);

-- レート制限の数え上げ(アドレス・IP は HMAC だけ。24 時間で削除)
CREATE TABLE rate_events (
  site_id TEXT NOT NULL,
  kind TEXT NOT NULL,                     -- 'email_addr' | 'email_site' | 'login_ip' | 'member'
  key_hash TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX idx_rate_events ON rate_events(site_id, kind, key_hash, at);
CREATE INDEX idx_rate_events_at ON rate_events(at);

-- MAU(サイト・月・アドレスの HMAC。当月と前月だけ残す)
CREATE TABLE mau (
  site_id TEXT NOT NULL,
  month TEXT NOT NULL,                    -- 'YYYY-MM'(UTC)
  member_hash TEXT NOT NULL,
  PRIMARY KEY (site_id, month, member_hash)
);

-- 操作ログ(個人情報なし。アドレスは HMAC。30 日)
CREATE TABLE ops_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL,
  page_id TEXT,
  actor TEXT NOT NULL,                    -- 'plugin' | 'member' | 'system'
  action TEXT NOT NULL,
  detail TEXT,                            -- JSON(レコードの内容・アドレス・トークンは入れない)
  at TEXT NOT NULL
);
CREATE INDEX idx_ops_log_site ON ops_log(site_id, at);
CREATE INDEX idx_ops_log_at ON ops_log(at);

-- LINE ログイン(設計 §4.2.10。M3)。契約者自身の LINE ログインのチャネルをサイト単位で持つ。
--   line_channel_id: チャネル ID(秘密ではない)/ line_secret_enc: チャネルシークレット(サイト DEK で暗号化。API 応答に返さない)
--   dek_wrapped: サイト DEK を VAULT_KEK で包んだもの(LINE のシークレットを保存するときに作る)
-- LINE のユーザー ID は契約者の kintone にだけ保存し、当社は保存しない(連携用リンクは codes に kind='line_link' で 7 日)
ALTER TABLE sites ADD COLUMN line_channel_id TEXT;
ALTER TABLE sites ADD COLUMN line_secret_enc TEXT;
ALTER TABLE sites ADD COLUMN dek_wrapped TEXT;

-- メンバーの自己登録(設計 §19)。契約者が自己登録を有効にしたアプリだけ、レコード追加だけの権限を持つ第 2 トークンを持つ。
--   add_token_enc: 追加専用トークン(ページ DEK で暗号化。API 応答に返さない)。登録時と毎日、追加だけであることを検証する
ALTER TABLE pages ADD COLUMN add_token_enc TEXT;
ALTER TABLE pages ADD COLUMN add_token_last4 TEXT;
ALTER TABLE pages ADD COLUMN add_token_verified_at TEXT;
ALTER TABLE pages ADD COLUMN add_token_error TEXT;
