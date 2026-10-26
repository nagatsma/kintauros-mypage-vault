-- P3: メンバーのデータ(閲覧・編集・添付・自己登録・LINE 連携)を保管庫へ(VAULT 設計 §6)。
--   usage_counters: 量の上限の数え上げ(§6.2-5・V6)。kind 'session_records' = 1 セッションが 1 時間に取得したレコード数(key は sid の SHA-256)。
--                   bucket は UTC の 1 時間('YYYY-MM-DDTHH')。先に数を入れてから比べる(並列でも上限を超えない)。日次の掃除で古い時間を消す
--   codes の kind に次が加わる(どれも 1 回限り・期限で消える。レコードの内容・アドレスは入れない):
--     'line_done'   LINE の連携の完了(LINE のユーザー ID・連携用リンク / メンバー自身の連携の相手のセッション。10 分)
--     'signup_used' 自己登録のトークンの使用中・使用済みの印(id はトークンの SHA-256。二重の登録を防ぐ。トークンの期限まで)
CREATE TABLE usage_counters (
  site_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  bucket TEXT NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (site_id, kind, key_hash, bucket)
);
CREATE INDEX idx_usage_counters_bucket ON usage_counters(bucket);
