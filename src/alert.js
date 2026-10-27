// 異常の通知(VAULT 設計 §6.2-5・§14.5「P4b の 4 の決定」)。サイト全体の確認コードの失敗数が上限を超えたら、
//   当社(環境変数 ALERT_EMAIL)と契約者の管理者(ドメイン全体の設定の notifyEmail)にメールする。サイト自体は止めない。
//   通知はサイトごとに UTC の 1 時間に 1 回まで(usage_counters に先に数を入れてから、1 件目のときだけ送る。並列でも二重に送らない)。
//   本文に上限の値・メンバーのアドレス・確認コードを入れない。宛先はログに出さない
import { siteUrlOf } from './api.js';
import { logOp } from './db.js';
import { sendEmail } from './kit/email.js';

const hourBucket = (d = new Date()) => d.toISOString().slice(0, 13);

// この 1 時間で最初の通知なら true(数を入れてから返す)
async function firstInHour(env, site, key) {
  const row = await env.DB.prepare('INSERT INTO usage_counters (site_id, kind, key_hash, bucket, n) VALUES (?, ?, ?, ?, 1) ON CONFLICT(site_id, kind, key_hash, bucket) DO UPDATE SET n = n + 1 RETURNING n')
    .bind(site.id, 'alert', key, hourBucket()).first();
  return !!row && Number(row.n) === 1;
}

export async function alertCodeFails(env, site) {
  if (!(await firstInHour(env, site, 'code_fail'))) return;
  await logOp(env.DB, site.id, null, 'system', 'code_fail_limit', null);
  if (!env.RESEND_API_KEY) return console.log('[alert skipped] RESEND_API_KEY is not configured');
  const name = site.settings.name || site.slug;
  const url = siteUrlOf(env, site);
  const from = env.MAIL_FROM || 'KINTAUROS マイページ <noreply@kintauros.com>';
  const sends = [];
  if (env.ALERT_EMAIL) {
    const m = codeFailMail('ja', { siteName: name, url, domain: site.domain, forCompany: true });
    sends.push(sendEmail(env, { to: env.ALERT_EMAIL, subject: m.subject, text: m.text, from }, { logTo: false }));
  }
  if (site.settings.notifyEmail) {
    const m = codeFailMail(site.settings.lang || 'ja', { siteName: name, url });
    sends.push(sendEmail(env, { to: site.settings.notifyEmail, subject: m.subject, text: m.text, from }, { logTo: false }));
  }
  await Promise.all(sends);
}

export function codeFailMail(lang, { siteName, url, domain = '', forCompany = false }) {
  if (forCompany) {
    return {
      subject: `[マイページ 警報] ${siteName}: 確認コードの失敗がサイト全体の上限を超えました`,
      text: `サイト: ${siteName}\nURL: ${url}\nkintone: ${domain}\n\n直近 1 時間の確認コードの照合の失敗が、サイト全体の上限(LIMIT_CODE_FAILS_PER_SITE_HOUR)を超えました。確認コードでのログインを止めています(失敗が減れば自動で戻ります)。\n多数のアドレスにばらした総当たりの可能性があります。保管庫の D1(ops_log・rate_events)と Worker のログを確認してください。\n\n管理者の通知先が設定されていれば、契約者にも知らせています。`,
    };
  }
  const M = {
    ja: { subject: `【KINTAUROS マイページ】${siteName}: 確認コードでのログインを一時的に止めています`, text: `${siteName} のマイページ(${url})で、確認コードの入力の失敗がこの 1 時間に多数ありました。メンバーのメールアドレスを使った不正なログインの試みの可能性があるため、確認コードでのログインを一時的に止めています。\n\n・止まっているもの: メールの確認コードでのログイン(失敗が減ると 1 時間ほどで自動的に戻ります)\n・そのまま使えるもの: Google・LINE でのログイン、ログイン済みのメンバーの画面\n\nこの通知は KINTAUROS にも届いています。お手数ですが、心当たりのない場合や続く場合は KINTAUROS のお問い合わせ窓口へご連絡ください。\n\n--\nこの通知の宛先は、マイページ プラグインの設定画面「ドメイン全体」の「管理者の通知先」で変更できます。このメールは自動送信しています。返信しても届きません。` },
    en: { subject: `[KINTAUROS My Page] ${siteName}: sign-in with verification codes is temporarily stopped`, text: `On the member page of ${siteName} (${url}), there were many failed verification code entries in the last hour. Because this may be an attempt to sign in with members' email addresses without permission, sign-in with verification codes is temporarily stopped.\n\n- Stopped: sign-in with email verification codes (it resumes automatically within about an hour once the failures decrease)\n- Still available: sign-in with Google and LINE, and member pages for members who are already signed in\n\nKINTAUROS has also received this notice. If you do not recognize this or it continues, please contact KINTAUROS support.\n\n--\nYou can change the recipient of this notice in "Administrator notifications" on the "Whole domain" tab of the My Page plug-in settings. This message was sent automatically. Replies are not delivered.` },
    zh: { subject: `【KINTAUROS 我的页面】${siteName}: 已暂时停止使用验证码登录`, text: `${siteName} 的会员页面(${url})在过去 1 小时内出现了大量验证码输入失败。由于这可能是有人使用会员的邮箱地址进行非法登录的尝试，已暂时停止使用验证码登录。\n\n・已停止: 使用邮件验证码登录(失败减少后约 1 小时内会自动恢复)\n・仍可使用: 使用 Google・LINE 登录，以及已登录会员的页面\n\nKINTAUROS 也已收到此通知。如果您没有头绪或情况持续，请联系 KINTAUROS 的咨询窗口。\n\n--\n此通知的收件人可以在我的页面插件设置画面「整个域名」的「管理员通知地址」中更改。本邮件为自动发送。回复本邮件不会送达。` },
    'zh-TW': { subject: `【KINTAUROS 我的頁面】${siteName}: 已暫時停止使用驗證碼登入`, text: `${siteName} 的會員頁面(${url})在過去 1 小時內出現了大量驗證碼輸入失敗。由於這可能是有人使用會員的電子郵件地址進行非法登入的嘗試，已暫時停止使用驗證碼登入。\n\n・已停止: 使用電子郵件驗證碼登入(失敗減少後約 1 小時內會自動恢復)\n・仍可使用: 使用 Google・LINE 登入，以及已登入會員的頁面\n\nKINTAUROS 也已收到此通知。若您沒有頭緒或情況持續，請聯絡 KINTAUROS 的諮詢窗口。\n\n--\n此通知的收件人可以在我的頁面外掛程式設定畫面「整個網域」的「管理員通知地址」中變更。本郵件為自動發送。回覆本郵件不會送達。` },
  };
  return M[lang] || M.ja;
}
