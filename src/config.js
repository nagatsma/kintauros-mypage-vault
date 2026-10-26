// KINTAUROS マイページ 保管庫の定数(mypage-worker の config.js と同じ値。P4 で画面側から消すまで両方にある)。
// 異常を検知する量の上限(1 セッションの取得件数など。設計 §6.2-5)の値はここに書かない — 公開リポジトリなので、
// 値は保管庫の Worker の環境変数(ダッシュボードで設定。wrangler.toml の keep_vars で保持)から読む(LIMIT_VARS)

export const MYPAGE_PLUGIN_ID = 'mypage'; // license-api の PLUGINS / plans(M3 で PLANS.mypage を追加)

// サイト(サブドメイン)・ページ(パス)の slug
export const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/;
export const PAGE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$|^[a-z0-9]$/;
export const RESERVED_SITE_SLUGS = new Set([
  'api', 'auth', 'www', 'origin', 'admin', 'app', 'apps', 'mail', 'ftp', 'ns', 'ns1', 'ns2', 'dev', 'test', 'staging',
  'status', 'help', 'docs', 'blog', 'static', 'cdn', 'assets', 'files', 'kintauros', 'kintone', 'cybozu', 'login', 'my', 'mypage',
]);
export const RESERVED_PAGE_SLUGS = new Set(['assets', 'f', 'health', 'api', 'robots.txt', 'favicon.ico', 'logo', 'index.html', '_login', '_auth', '_logout', '_menu']);

// 本人確認(設計 §4.2.5 / §4.2.8)
export const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;      // 確認コードの有効期間
export const EMAIL_CODE_ATTEMPTS = 5;                  // 試行回数
export const EMAIL_SENDS_PER_ADDRESS_10MIN = 3;        // 同じアドレスへの送信数
export const EMAIL_SENDS_PER_SITE_HOUR = 300;          // サイトごとの 1 時間の送信数
export const HANDOFF_TTL_MS = 60 * 1000;               // 受け渡しコード(auth ホスト → 各サイト)
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;      // Google の state
export const SESSION_DAYS_DEFAULT = 90;                // ログインの有効期間(サイト設定で 1〜180 日)
export const SESSION_DAYS_MIN = 1;
export const SESSION_DAYS_MAX = 180;
export const SESSION_RENEW_AFTER_MS = 24 * 60 * 60 * 1000; // 使うたびに延長(1 日 1 回書き直す)
export const MENU_REFRESH_MS = 24 * 60 * 60 * 1000;    // メニュー(入れるページの一覧)の確認は 1 日 1 回
export const LOGIN_ATTEMPTS_PER_IP_10MIN = 60;         // ログイン画面の POST(IP の HMAC で数える。IP は画面側が渡す値なので目安)
export const EMAIL_CODE_TRIES_PER_ADDRESS_HOUR = 10;   // 同じアドレスの確認コードの照合の回数(コードをまたいで数える。総当たりの上限)
export const OAUTH_BIND_MIN = 32;                      // OAuth の開始時に返すブラウザとの結び付けの値の長さ(画面側が auth ホストの Cookie に入れる)
// 異常を検知する量の上限(設計 §6.2-5)は環境変数(ダッシュボードで設定。未設定なら検査しない)。名前だけここに書く
export const LIMIT_VARS = {
  codeFailsPerSiteHour: 'LIMIT_CODE_FAILS_PER_SITE_HOUR', // サイト全体の 1 時間の確認コードの照合の失敗数。超えたらそのサイトの照合を止める(通知は P4)
  // P3(閲覧・編集・添付)。この 2 つは必須: 未設定ならメンバーのデータの API は 503(上限なしで開かない)
  memberRequestsPerMin: 'LIMIT_MEMBER_REQUESTS_PER_MIN',  // メンバーごとの 1 分の呼び出し回数(設計 §4.6.3)。超えたら 429
  recordsPerSessionHour: 'LIMIT_RECORDS_PER_SESSION_HOUR', // 1 セッションが 1 時間(UTC の時刻の区切り)に取得するレコード数(§6.2-5・V6)。超えたら 429(停止と通知は P4)
};

// kintone の API 上限を食いつぶさない(設計 §4.6.3)
export const SITE_CONCURRENCY = 10;                    // サイト(ドメイン)ごとの同時接続
export const SITE_QUEUE_WAIT_MS = 5000;                // 空くまで待つ上限
export const PAGE_DAILY_LIMIT_DEFAULT = 5000;          // ページ(アプリ)ごとの 1 日の回数(既定は kintone の上限の半分)
export const PAGE_DAILY_LIMIT_MAX = 100000;
export const KINTONE_TIMEOUT_MS = 8000;
export const KINTONE_FILE_TIMEOUT_MS = 30000;

// フィールド定義のキャッシュ(個人情報を含まないので短時間キャッシュする。§4.4)
export const FORM_CACHE_MS = 5 * 60 * 1000;

// 一覧(§4.3.1)
export const LIST_PAGE_SIZE = 20;
export const LIST_MAX_OFFSET = 10000;                  // kintone の offset の上限
export const LIST_FIELDS_MAX = 8;
export const SEARCH_KEYWORD_MAX = 100;

// 添付(§4.4)。保管庫が署名した添付の識別子(ダウンロード・編集での削除の指定)の有効期間。編集フォーム(CSRF)と同じ
export const FILE_LINK_TTL_MS = 2 * 60 * 60 * 1000;
export const UPLOAD_HANDLE_TTL_MS = 2 * 60 * 60 * 1000; // アップロード済みの添付の識別子(保存で使う。kintone の fileKey は 3 日で失効)

// 編集(§4.5 / §4.5.1。M2)
export const CSRF_TTL_MS = 2 * 60 * 60 * 1000;         // フォームごとのトークン(CSRF)の有効期間
export const FILES_PER_REQUEST = 5;                    // 1 回の保存で追加できる添付の数(フィールド・列ごと)
export const UPLOAD_TOTAL_BYTES = 30 * 1024 * 1024;    // 1 回の保存の multipart 全体(1 ファイル 10MB は worker-kit FILE_MAX_BYTES)
export const TEXT_INPUT_MAX = 64000;                   // kintone の文字列 1 行の上限
export const LAST_LOGIN_MAX_RECORDS = 20;              // 最終ログイン日時を書き込むレコード数の上限(1 ページあたり)
export const COMMENT_MAX = 1000;                       // 操作の記録(レコードのコメント)の長さ
export const SAVE_BODY_MAX = 1024 * 1024;              // 保存の JSON の大きさの上限(添付は別に送る)
export const SAVE_OPS_MAX = 50;                        // 1 回の保存で受け付ける行の操作の数
export const LINE_DONE_TTL_MS = 10 * 60 * 1000;        // LINE の連携(連携用リンク・メンバー自身の連携)の完了から書き込みまでの猶予

// 設定値の上限
export const SITE_NAME_MAX = 60;
export const PAGE_NAME_MAX = 60;
export const CONDITION_MAX = 1000;
export const CONTACT_MAX = 500;
export const URL_MAX = 500;
export const THEME_COLOR_RE = /^#[0-9a-fA-F]{6}$/;
export const THEME_COLOR_DEFAULT = '#1a73e8';

// ライセンス(publish-worker と同じ運用: 24 時間ごとに再確認。失効後 7 日猶予 → 停止 → 30 日で削除。§6)
export const LICENSE_RECHECK_MS = 24 * 60 * 60 * 1000;
export const LICENSE_GRACE_DAYS = 7;
export const LICENSE_PURGE_DAYS = 30;
export const DAY_MS = 24 * 60 * 60 * 1000;

// 保持(§6)
export const OPS_LOG_KEEP_DAYS = 30;
export const RATE_EVENTS_KEEP_MS = 24 * 60 * 60 * 1000;

export const LANGS = ['ja', 'en', 'zh', 'zh-TW'];

// LINE ログイン(§4.2.10。M3)
export const LINE_LINK_DAYS_DEFAULT = 7;                 // 連携用リンクの有効期間(日)
export const LINE_LINK_DAYS_MIN = 1;
export const LINE_LINK_DAYS_MAX = 30;
export const LINE_CHANNEL_ID_RE = /^\d{6,20}$/;
export const LINE_SECRET_RE = /^[A-Za-z0-9]{16,64}$/;

// 自己登録(§19)
export const SIGNUP_TOKEN_TTL_MS = 30 * 60 * 1000;      // 本人確認から登録画面の送信までの猶予
export const SIGNUP_FIELDS_MAX = 20;
export const SIGNUP_CONSENT_MAX = 1000;
