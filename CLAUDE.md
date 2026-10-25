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

## テスト

```bash
npm test          # vitest。D1 は node:sqlite に migrations を当てた代役、kintone とゲートも代役(test/helpers.js)
npm run check     # wrangler deploy --dry-run(バンドルの確認。Cloudflare には送らない)
```
