// 複製元: kintauros-plugins の packages/worker-kit/src/domain.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
// kintone ドメインの正規化(license-api/src/domain.js と同じ規則。SERVICE-POLICY §1)。
// Worker の接続先を契約ドメインに限定する(SSRF 防止)ため、正規化できない入力は null を返す
const KINTONE_SUFFIXES = ['cybozu.com', 'kintone.com', 'cybozu.cn'];
const SUBDOMAIN_RE = /^[a-z0-9][a-z0-9-]{0,61}$/;

export function normalizeKintoneDomain(input) {
  if (typeof input !== 'string') return null;
  let host = input.trim().toLowerCase();
  host = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  for (const suffix of KINTONE_SUFFIXES) {
    if (!host.endsWith('.' + suffix)) continue;
    let sub = host.slice(0, -(suffix.length + 1));
    if (sub.endsWith('.s')) sub = sub.slice(0, -2); // セキュアアクセス
    if (!SUBDOMAIN_RE.test(sub)) return null;
    return `${sub}.${suffix}`;
  }
  return null;
}
