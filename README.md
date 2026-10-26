# KINTAUROS マイページ 保管庫

[KINTAUROS マイページ](https://kintauros.com/) の、kintone の API トークンと本人確認の秘密を預かる Cloudflare Worker です。メンバーの画面を配信するサーバーとは別の Cloudflare アカウントで動かし、画面側が侵害されても契約者の kintone のレコードを一括で読み出せないようにしています。

- トークンは暗号化して保存し、**外へ返す機能を持ちません**。kintone への呼び出しは保管庫が行い、結果だけを返します
- トークンは登録時と毎日、「レコード閲覧」「レコード編集」だけであることを検証し、権限が広げられていたら破棄します(自己登録用の「レコード追加」だけのトークンも同様)
- 接続先は契約した kintone のドメインだけです
- メンバーの本人確認(メールの確認コード・Google・LINE)は保管庫が検証し、ログインの状態(セッション)は保管庫だけが持つ鍵で署名します。画面のサーバーはセッションを作れないので、画面側が侵害されても他人になりすませません
- デプロイは GitHub Actions からだけで、`main` へのマージ後に当社の運営者が承認したときだけ行います

このリポジトリは仕組みを確認できるように公開していますが、利用を許諾するものではありません(ライセンスはありません)。秘密の値はコードに含めず、Cloudflare と GitHub のシークレットにだけ置いています。

## 構成

| パス | 内容 |
|---|---|
| `GET /health` | 死活確認 |
| `/api/*` | 管理 API(マイページ プラグインの設定画面から。認証はプラグインが作るページ鍵) |
| `/v1/*` | メンバー向け(画面のサーバーからサーバー間で。本人確認・セッション。認証はメンバーのセッション) |
| `src/kit/` | 共通部品(kintone 呼び出し・暗号化など)。別リポジトリから同期するため、直接は直さない |

D1(サイト・ページの設定、暗号化したトークン)と Durable Object(kintone への同時接続と 1 日の回数の制御)を使います。レコードの内容・添付ファイルは保存しません。

## 開発

```bash
npm ci
npm test
echo "VAULT_KEK=$(openssl rand -base64 32)" > .dev.vars   # ローカル用の鍵(コミットしない)
echo "VAULT_SESSION_KEY=$(openssl rand -base64 32)" >> .dev.vars
echo "VAULT_FRONT_KEY=$(openssl rand -hex 24)" >> .dev.vars
npm run migrate:local
npm run dev                                               # http://localhost:8789/health
```
