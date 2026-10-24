// QR コード(SVG)。メンバー証と LINE 連携用リンクで使う。
//   メンバーの画面は CSP script-src 'self' で外部ライブラリを読めないので、Worker 側で SVG を作って埋め込む。
//   エンコーダーは qrcode-generator(MIT。依存なし・Web Crypto や DOM に依存しない)。誤り訂正 M・バイトモード(UTF-8)
import qrcode from 'qrcode-generator';

export const QR_TEXT_MAX = 500;

// 戻り値: SVG 文字列(viewBox 付き・幅は CSS で決める)| ''(空の値・長すぎる値)
export function qrSvg(text, { margin = 2, className = 'qr', label = '' } = {}) {
  const s = String(text == null ? '' : text);
  if (!s || s.length > QR_TEXT_MAX) return '';
  let qr;
  try {
    qr = qrcode(0, 'M'); // 型番は自動
    qr.addData(s, 'Byte');
    qr.make();
  } catch {
    return '';
  }
  const n = qr.getModuleCount();
  const size = n + margin * 2;
  const parts = [];
  for (let r = 0; r < n; r++) {
    let run = -1;
    for (let c = 0; c <= n; c++) {
      const dark = c < n && qr.isDark(r, c);
      if (dark && run < 0) run = c;
      if (!dark && run >= 0) {
        parts.push(`M${run + margin} ${r + margin}h${c - run}v1h-${c - run}z`);
        run = -1;
      }
    }
  }
  const title = label ? `<title>${label.replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch])}</title>` : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" class="${className}" shape-rendering="crispEdges" role="img">${title}<rect width="${size}" height="${size}" fill="#fff"/><path d="${parts.join('')}" fill="#000"/></svg>`;
}
