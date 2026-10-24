// CORS: 管理 API は顧客の kintone ドメイン上のプラグイン JS(設定画面からの直接 fetch)から呼ばれる。
// 許可オリジンは publish-worker / license-api と同じ(kintone 3 リージョン+セキュアアクセス+自社サイト)
const ALLOWED_ORIGIN_RE = /^https:\/\/[a-z0-9][a-z0-9-]{0,61}\.(s\.)?(cybozu\.com|kintone\.com|cybozu\.cn)$/;

export function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGIN_RE.test(origin) || origin === 'https://kintauros.com' || origin === 'https://www.kintauros.com';
  if (!allowed) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Kintauros-Mypage-Key',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
