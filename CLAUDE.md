# kintauros-mypage-vault(KINTAUROS マイページ 保管庫)

**公開リポジトリ**。設計・判断事項・運用の詳細は非公開リポジトリ kintauros-plugins の `docs/MYPAGE-VAULT-DESIGN-2026-10.md`(正)と `mypage-worker/CLAUDE.md` にある。ここには保管庫の作業で必ず守ることだけを書く。

## 必ず守ること

- **開発機から `wrangler deploy` しない・デプロイの承認をしない**。デプロイは main へのマージ後の GitHub Actions(environment `production`)だけで、承認は当社の運営者が GitHub の Web から行う。Claude Code のセッションは修正・テスト・PR の作成・デプロイ結果の確認(Actions のログ)まで。`wrangler d1 execute --remote`・`wrangler secret put` も行わない(開発機には保管庫のアカウントの鍵が無い)
- **秘密の値・異常を検知する量の上限の値をコードに書かない**(公開リポジトリ)。秘密は Worker のシークレット(`VAULT_KEK` など。保管庫のアカウントのダッシュボードで登録)、上限は保管庫の Worker の環境変数(ダッシュボードで設定。`keep_vars = true` で保持)。ログ・テストのフィクスチャにも実在のトークン・ドメインを書かない
- **トークンを返す API を作らない**。状態は末尾 4 文字・検証日時・エラーだけ。D1 の書き出しや管理用のエンドポイントも作らない。任意の kintone クエリを受ける API も作らない(設計 §6)
- サイト全体の設定・一斉ログアウト・LINE は、閲覧+編集のトークンを登録して検証に通ったページの鍵だけ(`src/auth.js isSiteAdmin`。設計 §7)
- レコードの内容・添付を D1・ログ・Cache に置かない。Worker のログにアドレス・レコード・トークンを出さない。D1 は必ず `.bind()`。kintone の接続先は `normalizeKintoneDomain` で正規化した契約ドメインだけ
- `src/kit/` と `test/kit.test.js` は kintauros-plugins の `packages/worker-kit` の複製。**直接直さない**。直すときは worker-kit を直し、kintauros-plugins で `node scripts/sync-vault-kit.mjs` を実行して揃え、どちらを直したかを PR に書く
- 依存パッケージは最小にし、版を固定する(`.npmrc` の `save-exact`・`ignore-scripts`。lockfile をコミット)。GitHub Actions の外部 Action はコミットの SHA で固定する
- LICENSE は置かない(公開するが利用は許諾しない)
- `VAULT_KEK` は再生成しない(変えると保管庫の全トークン・LINE のシークレットが復号できなくなる)
- **メンバー向け(`/v1/*`。`src/v1.js`)は画面側(mypage-worker)が乗っ取られている前提で作る**。権限の根拠はセッション(`VAULT_SESSION_KEY` で署名。`src/session.js`)と本人確認(確認コード・Google/LINE の ID トークン)だけ。`X-Mypage-Front-Key` は雑多な呼び出し除けで、根拠にしない。画面側の申告(ホスト名・IP・戻り先)は保管庫で引き直すか目安としてだけ使う
- 本人確認を経ずにセッションを返す経路を作らない。セッションの検証(署名・サイト・期限・`session_epoch`・ログアウト済み)を省かない。確認コード・コードのハッシュ・verifier・シークレット・トークンを応答とログに出さない(kit の `sendEmail` は件名をログに出すので、送信キーが無いときは呼ばない)
- 回数の上限は「読んでから書く」にしない(並列の呼び出しですり抜ける)。確保してから比べる(`reserveCodeAttempt`)・先に数を入れてから数える(`overLimit`)・取り出して消す(`takeCode`)
- **メンバーのデータ(P3。`src/member-data.js`)**: 照合の条件は保管庫が組み立て(`match.js`)、取得後に必ず再照合する(`identMatches`)。レコード番号だけで開ける・書ける経路を作らない。返すのは閲覧を許したフィールド・列・行だけ(kintone への `fields` 指定と `view.js` の削り込みの両方。定義・レイアウトも `publicFields` / `publicLayout` で絞る)
- 編集は入力値だけを受け取り `edit.js` で検証して PUT を組み立てる。組み立て済みの本文を受け付けない。**照合に使うフィールド(メールアドレス・LINE 連携 ID。メンバー表の列を含む)を既存の行で書き換えさせない**(メンバー表の行の追加でだけメールアドレスを入れられる。LINE 連携 ID は LINE の連携でだけ書く)。行の権限(行の作成者)も保管庫で確かめる
- 添付は保管庫が署名した識別子だけ(`INFO.file` はセッション・ページ・レコード、`INFO.upload` はセッション・ページに結び付ける)。応答に fileKey を出さない。中継だけで保存しない
- 量の上限 `LIMIT_MEMBER_REQUESTS_PER_MIN`・`LIMIT_RECORDS_PER_SESSION_HOUR` は必須(未設定ならデータの API を開かない)。数え方は `quota.js`(先に確保してから比べ、使わなかった分を戻す)
- 実装をわざと壊すとテストが落ちることを、認可・署名・回数の上限・秘密の漏れについて確かめる(`test/member-auth.test.js`・`test/member-data.test.js`。並列の競合は `slowD1` で再現する)

## テスト

```bash
npm test          # vitest。D1 は node:sqlite に migrations を当てた代役、kintone とゲートも代役(test/helpers.js)
npm run check     # wrangler deploy --dry-run(バンドルの確認。Cloudflare には送らない)
```
