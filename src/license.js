// KINTAUROS ライセンスサーバー(api.kintauros.com)へのマイページライセンス照会(publish-worker と同じ運用。サイト = ドメイン単位)
import { DAY_MS, LICENSE_GRACE_DAYS, LICENSE_PURGE_DAYS, LICENSE_RECHECK_MS, MYPAGE_PLUGIN_ID } from './config.js';
import { nowIso } from './util.js';

// 戻り値: { ok: true|false|null, status, plan, expiresAt }。null は API 到達不可(判定保留)
export async function checkMypageLicense(env, domain) {
  const url = `${env.LICENSE_API_BASE}/api/license?domain=${encodeURIComponent(domain)}&plugin=${MYPAGE_PLUGIN_ID}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 6000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'kintauros-mypage-vault' } });
    if (!res.ok) return { ok: null, status: 'unknown', error: `http_${res.status}` };
    const body = await res.json();
    const ok = body.status === 'active' || body.status === 'trial';
    return { ok, status: body.status, plan: body.plan || null, expiresAt: body.expiresAt || null };
  } catch (err) {
    return { ok: null, status: 'unknown', error: String(err && err.message) };
  } finally {
    clearTimeout(timer);
  }
}

// 失効後の扱い(§6): 猶予 7 日は表示継続 → 停止 → 失効から 30 日で設定・トークンを削除
export function licenseServeState({ licenseStatus, licenseExpiresAt, now }) {
  if (licenseStatus === 'active' || licenseStatus === 'trial') return { serve: true, purgeAfter: null };
  const expired = licenseExpiresAt ? Date.parse(licenseExpiresAt) : NaN;
  const base = Number.isFinite(expired) ? expired : now;
  const serve = now < base + LICENSE_GRACE_DAYS * DAY_MS;
  return { serve, purgeAfter: new Date(base + LICENSE_PURGE_DAYS * DAY_MS).toISOString() };
}

// 24 時間以上前の確認なら取り直して sites を更新する。戻り値: 取り直したときだけ結果
export async function refreshLicenseIfStale(env, site, now = Date.now()) {
  const checked = site.license_checked_at ? Date.parse(site.license_checked_at) : 0;
  if (now - checked < LICENSE_RECHECK_MS) return null;
  const lic = await checkMypageLicense(env, site.domain);
  if (lic.ok === null) return lic;
  await env.DB.prepare('UPDATE sites SET license_status = ?, license_plan = ?, license_expires_at = ?, license_checked_at = ? WHERE id = ?')
    .bind(lic.status, lic.plan, lic.expiresAt, nowIso(), site.id).run();
  site.license_status = lic.status;
  site.license_plan = lic.plan;
  site.license_expires_at = lic.expiresAt;
  return lic;
}

export const isTrial = (site) => site.license_status === 'trial';
