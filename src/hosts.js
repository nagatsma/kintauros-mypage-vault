// メンバーの画面のホスト名 → サイト。画面側は X-Mypage-Host でホスト名を渡す(信頼はしない。保管庫が D1 で引き直す)
import { getSiteByCustomHost, getSiteBySlug } from './db.js';
import { licenseServeState } from './license.js';

const HOST_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

export async function resolveSiteByHost(env, rawHost) {
  const host = String(rawHost || '').trim().toLowerCase();
  if (host.length > 253 || !HOST_RE.test(host)) return null;
  const suffix = `.${env.PUBLIC_BASE_DOMAIN}`;
  if (host.endsWith(suffix)) {
    const slug = host.slice(0, -suffix.length);
    if (slug.includes('.')) return null;
    return getSiteBySlug(env.DB, slug);
  }
  return getSiteByCustomHost(env.DB, host);
}
export const hostBelongs = (env, site, host) => host === `${site.slug}.${env.PUBLIC_BASE_DOMAIN}` || (!!site.custom_host && host === site.custom_host);

// メンバーに見せてよいサイトか(停止・ライセンス失効の猶予切れは不可。画面側の member.js と同じ判定)
export const siteServing = (site, now = Date.now()) => site.status === 'active' && licenseServeState({ licenseStatus: site.license_status, licenseExpiresAt: site.license_expires_at, now }).serve;
