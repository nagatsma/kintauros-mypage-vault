// 複製元: kintauros-plugins の packages/worker-kit/src/email.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
// メール送信(Resend)。RESEND_API_KEY 未設定なら送信をスキップする(開発中に外部送信しないための安全弁)。
// 本文にレコードの内容・確認コード以外の秘密を入れない。宛先アドレスはログに残さない用途では呼び出し側で伏せる
export async function sendEmail(env, { to, subject, text, from, replyTo }, { defaultFrom = 'KINTAUROS <noreply@kintauros.com>', logTo = true } = {}) {
  if (!to) return { sent: false, reason: 'no_recipient' };
  if (!env.RESEND_API_KEY) {
    console.log(`[email skipped] to=${logTo ? to : '(hidden)'} subject=${subject}`);
    return { sent: false, reason: 'no_api_key' };
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: from || env.MAIL_FROM || defaultFrom, to: [to], subject, text, ...(replyTo ? { reply_to: replyTo } : {}) }),
  });
  if (!res.ok) {
    console.error(`[email error] ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return { sent: false, reason: 'api_error' };
  }
  return { sent: true };
}
