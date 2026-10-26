// 回数と量の上限(VAULT 設計 §6.2-5・§6.2-6・V6)。どれも「先に数を入れてから比べる」(読んでから書くと並列の呼び出しですり抜ける)。
//   異常を検知する上限の値は公開リポジトリに書かない。保管庫の Worker の環境変数(LIMIT_VARS。ダッシュボードで設定)から読む。
//   kintone の API 上限(サイトの同時接続・アプリごとの 1 日の回数)は SiteGate(gate.js)が kintone の呼び出しごとに守る
import { LIMIT_VARS } from './config.js';
import { addRate, countRate } from './db.js';
import { sha256Hex } from './util.js';

const since = (ms) => new Date(Date.now() - ms).toISOString();

// rate_events に 1 件入れてから、窓の中の件数が max を超えたかを返す
export async function overLimit(env, site, kind, key, windowMs, max) {
  await addRate(env.DB, site.id, kind, key);
  return (await countRate(env.DB, site.id, kind, key, since(windowMs))) > max;
}

// 環境変数の上限(正の整数)。未設定・不正なら 0
export const siteLimit = (env, name) => {
  const n = Number(env[LIMIT_VARS[name]]);
  return Number.isInteger(n) && n > 0 ? n : 0;
};

// メンバーのデータの API に要る上限が揃っているか(揃っていなければ上限なしで開かない)
export const dataLimitsConfigured = (env) => siteLimit(env, 'memberRequestsPerMin') > 0 && siteLimit(env, 'recordsPerSessionHour') > 0;

// メンバーごとの 1 分の呼び出し回数。memberKey は identHash
export const memberOverRate = (env, site, memberKey) => overLimit(env, site, 'member', memberKey, 60 * 1000, siteLimit(env, 'memberRequestsPerMin'));

// 1 セッションが 1 時間に取得するレコード数。取得の前に最大数を確保し、取得の後に使わなかった分を返す。
//   戻り値: { ok: true, settle(used) } | { ok: false }(確保できなかった。確保した分は返してある)
const hourBucket = (d = new Date()) => d.toISOString().slice(0, 13);
export async function reserveRecords(env, site, sid, n) {
  const limit = siteLimit(env, 'recordsPerSessionHour');
  const key = await sha256Hex(`sid:${sid}`);
  const bucket = hourBucket();
  const where = [site.id, 'session_records', key, bucket];
  const row = await env.DB.prepare('INSERT INTO usage_counters (site_id, kind, key_hash, bucket, n) VALUES (?, ?, ?, ?, ?) ON CONFLICT(site_id, kind, key_hash, bucket) DO UPDATE SET n = n + excluded.n RETURNING n')
    .bind(...where, n).first();
  const give = (k) => (k > 0 ? env.DB.prepare('UPDATE usage_counters SET n = max(0, n - ?) WHERE site_id = ? AND kind = ? AND key_hash = ? AND bucket = ?').bind(k, ...where).run() : null);
  if (!limit || !row || Number(row.n) > limit) {
    await give(n);
    return { ok: false };
  }
  return { ok: true, settle: (used) => give(n - Math.max(0, Math.min(n, used))) };
}
