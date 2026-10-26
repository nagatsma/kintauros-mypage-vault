// メンバーの本人確認とセッション(P2。VAULT 設計 §5・§6.1・§8)。
// 前提: 画面側(mypage-worker)は乗っ取られていて、攻撃者は画面側との共有の鍵を持ち、/v1 を任意の内容で呼べる。
// それでも「他人になりすましたセッションを作れない」「確認コードを総当たりできない」「応答に秘密が出ない」ことを確かめる
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index.js';
import { encryptSecret, encryptToken, newWrappedDek, sign } from '../src/crypto.js';
import { signIdTokenForTest } from '../src/line.js';
import { issueSession, SESSION_INFO } from '../src/session.js';
import { createD1, envOf, fakeKintone, KEK, seedPage, seedSite, slowD1, v1 } from './helpers.js';

const SITE = '11111111-1111-4111-8111-111111111111';
const OTHER_SITE = '33333333-3333-4333-8333-333333333333';
const PAGE = '22222222-2222-4222-8222-222222222222';
const OTHER_PAGE = '44444444-4444-4444-8444-444444444444';
const HOST = 'sample.kintauros.me';
const OTHER_HOST = 'other.kintauros.me';
const TOKEN = 'ViewEditToken0000000000000000000000001';
const VICTIM = 'victim@gmail.com';
const STRANGER = 'stranger@example.com';
const LINE_ID = 'U0123456789abcdef0123456789abcdef';
const LINE_CHANNEL = '1234567890';
const LINE_SECRET = 'abcdef0123456789abcdef0123456789';
const CLIENT_ID = 'test-client.apps.googleusercontent.com';
const GOOGLE_SECRET = 'GOCSPX-test-secret-00000000000000';
const RESEND = 're_test_resend_key_000000000000000';
const TURNSTILE = 'turnstile-secret-000000000000000000';
const RECORDS = [{ $id: { value: '5' }, メール: { value: 'Victim@Gmail.com' }, LINE: { value: LINE_ID } }];
const PAGE_SETTINGS = { name: 'ご契約', enabled: true, member: { field: 'メール', table: '' }, line: { field: 'LINE' }, condition: '', checkScope: 'all', checkPages: [], record: { lastLoginField: '最終ログイン' } };
const SITE_SETTINGS = { name: '本物の会社', login: { email: true, google: true }, sessionDays: 90, topCheckScope: 'all', topCheckPages: [], line: { enabled: true }, lang: 'ja' };

// ---- 外部(Resend・Google・LINE・Turnstile)の代役 ----
const te = new TextEncoder();
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jres = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
async function rsaKey(kid) {
  const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { kid, privateKey: kp.privateKey, pub: { kty: 'RSA', n: jwk.n, e: jwk.e, kid, alg: 'RS256', use: 'sig' } };
}
async function signRs(key, claims) {
  const h = b64url(te.encode(JSON.stringify({ alg: 'RS256', kid: key.kid, typ: 'JWT' })));
  const p = b64url(te.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key.privateKey, te.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}
const s256 = async (v) => b64url(await crypto.subtle.digest('SHA-256', te.encode(v)));

let google, attackerKey; // Google の鍵(JWKS に載る)と、攻撃者の鍵(載らない。kid は同じ)
beforeAll(async () => {
  google = await rsaKey('google-kid-1');
  attackerKey = await rsaKey('google-kid-1');
});

let db, kintone, env, mail, jobs, texts, secrets, idTokenFor, turnstileReply, providerCalls;
const ctx = { waitUntil: (p) => jobs.push(p) };
beforeEach(async () => {
  db = createD1();
  kintone = fakeKintone({ perms: { [TOKEN]: { read: true, edit: true } }, records: RECORDS });
  env = envOf(db, kintone, { GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: GOOGLE_SECRET, RESEND_API_KEY: RESEND, MAIL_FROM: 'KINTAUROS マイページ <noreply@kintauros.com>' });
  mail = [];
  jobs = [];
  texts = [];
  secrets = new Set([TOKEN, LINE_SECRET, GOOGLE_SECRET, RESEND, TURNSTILE, env.VAULT_KEK, env.VAULT_SESSION_KEY, env.VAULT_FRONT_KEY]);
  providerCalls = [];
  turnstileReply = { success: true, hostname: HOST };
  // 既定: Google は受け取った nonce で正しく署名した ID トークンを返す(テストごとに差し替える)
  idTokenFor = async ({ nonce }) => signRs(google, { iss: 'https://accounts.google.com', aud: CLIENT_ID, sub: 'g-1', email: VICTIM, email_verified: true, nonce, exp: Math.floor(Date.now() / 1000) + 600 });
  vi.stubGlobal('fetch', async (url, init = {}) => {
    const u = String(url);
    if (u === 'https://api.resend.com/emails') {
      mail.push(JSON.parse(init.body));
      return jres(200, { id: 'm' });
    }
    if (u === 'https://www.googleapis.com/oauth2/v3/certs') return jres(200, { keys: [google.pub] });
    if (u === 'https://oauth2.googleapis.com/token' || u === 'https://api.line.me/oauth2/v2.1/token') {
      const p = Object.fromEntries(new URLSearchParams(init.body));
      providerCalls.push({ url: u, ...p });
      // 本物と同じく、verifier が開始時の challenge に合わなければ断る(保管庫が自分の verifier を使っていることの確認)
      if ((await s256(p.code_verifier || '')) !== pending.challenge || p.code !== 'auth-code') return jres(400, { error: 'invalid_grant' });
      return jres(200, { id_token: await idTokenFor({ nonce: pending.nonce, params: p }) });
    }
    if (u.startsWith('https://challenges.cloudflare.com/')) return jres(200, turnstileReply);
    throw new Error(`unexpected fetch ${u}`);
  });
  await seedSite(db, { id: SITE, slug: 'sample', domain: 'sample.cybozu.com', settings: JSON.stringify(SITE_SETTINGS) });
  const dek = await newWrappedDek(env);
  await seedPage(db, { id: PAGE, site_id: SITE, app_id: '10', settings: JSON.stringify(PAGE_SETTINGS), dek_wrapped: dek, token_enc: await encryptToken(env, dek, TOKEN), token_last4: '0001', token_verified_at: new Date().toISOString() });
  // 別の会社のサイト(同じ本人のレコードがあるとする)
  await seedSite(db, { id: OTHER_SITE, slug: 'other', domain: 'other.cybozu.com', settings: JSON.stringify(SITE_SETTINGS) });
  const dek2 = await newWrappedDek(env);
  await seedPage(db, { id: OTHER_PAGE, site_id: OTHER_SITE, app_id: '10', settings: JSON.stringify(PAGE_SETTINGS), dek_wrapped: dek2, token_enc: await encryptToken(env, dek2, TOKEN) });
});
afterEach(() => vi.unstubAllGlobals());

// /v1 を画面側として呼ぶ。応答は記録し、D1 の一時データ(コードのハッシュ・verifier・bind のハッシュ)を秘密として集める
async function call(method, path, opts = {}) {
  const r = await v1(worker, env, method, path, { ctx, ...opts });
  texts.push(r.text);
  for (const row of db.rows('SELECT hash, data FROM codes')) {
    secrets.add(row.hash);
    const d = JSON.parse(row.data);
    if (d.v) secrets.add(d.v);
    if (d.b) secrets.add(d.b);
  }
  return r;
}
const codeOf = (m) => /確認コード: (\d{6})/.exec(m.subject)[1];
async function sendCode(email = VICTIM, opts = {}) {
  const r = await call('POST', '/v1/login/email', { body: { email, next: '/app10/' }, ...opts });
  return { r, codeId: r.body && r.body.codeId, code: mail.length ? codeOf(mail[mail.length - 1]) : null };
}
const verifyCode = (c, code, opts = {}) => call('POST', '/v1/login/email/verify', { body: { c, code }, ...opts });
const wrong = (code) => String((Number(code) + 1) % 1000000).padStart(6, '0');
let pending = {};
async function startOAuth(provider, body = {}) {
  const r = await call('POST', `/v1/login/${provider}/start`, { body: { next: '/app10/', ...body } });
  const u = new URL(r.body.url);
  pending = { state: u.searchParams.get('state'), nonce: u.searchParams.get('nonce'), challenge: u.searchParams.get('code_challenge'), bind: r.body.bind };
  return { r, url: u, ...pending };
}
const finish = (provider, { state = pending.state, bind = pending.bind, code = 'auth-code' } = {}) => call('POST', `/v1/login/${provider}/finish`, { host: null, body: { state, code, bind } });
const renew = (session, host = HOST) => call('POST', '/v1/session/renew', { session, host });

// どの応答にも秘密が出ないこと(各テストの最後に確かめる)
afterEach(() => {
  const all = texts.join('\n');
  for (const s of secrets) if (s) expect(all.includes(s), `応答に秘密が含まれている: ${s.slice(0, 6)}…`).toBe(false);
  for (const m of mail) {
    const code = codeOf(m);
    expect(all.includes(`"${code}"`), '応答に確認コードが含まれている').toBe(false);
  }
  for (const t of texts) expect(t).not.toMatch(/"(code|verifier|secret|token_enc|hash)"\s*:/);
});

describe('メールの確認コード', () => {
  it('登録済みのアドレスにだけ送り、応答は登録の有無で変えない。コードは保管庫の Resend キーで本人にだけ届く', async () => {
    const a = await sendCode(VICTIM, { body: { email: VICTIM, next: '/app10/', origin: 'https://evil.example', url: 'https://evil.example' } });
    const b = await call('POST', '/v1/login/email', { body: { email: STRANGER, next: '/' } });
    expect(a.r.status).toBe(200);
    expect(b.status).toBe(200);
    expect(Object.keys(a.r.body).sort()).toEqual(Object.keys(b.body).sort());
    expect(mail).toHaveLength(1);
    expect(mail[0].to).toEqual([VICTIM]);
    expect(mail[0].text).toContain('\n\nhttps://sample.kintauros.me\n\n'); // 画面側の申告ではなく、保管庫が解決したサイトの URL
    expect(mail[0].text).not.toContain('evil.example');
    expect(db.rows('SELECT hash FROM codes')[0].hash).not.toContain(a.code);
  });

  it('正しいコードでログインし、保管庫が署名したセッションを返す。MAU・最終ログイン日時も保管庫で書く', async () => {
    const { codeId, code } = await sendCode();
    const r = await verifyCode(codeId, code);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ ok: true, result: 'login', method: 'email', pageIds: [PAGE], next: '/app10/', member: { kind: 'email', label: VICTIM } });
    expect(r.body.session.maxAge).toBe(90 * 24 * 60 * 60);
    expect((await renew(r.body.session.value)).body).toMatchObject({ ok: true, member: { label: VICTIM }, method: 'email', renewed: null });
    await Promise.all(jobs);
    const put = kintone.calls.find((c) => c.method === 'PUT');
    expect(put.body).toMatchObject({ app: '10', id: '5', record: { 最終ログイン: {} } });
    expect(db.rows('SELECT COUNT(*) AS n FROM mau')[0].n).toBe(1);
    // コードは 1 回限り。D1 のどこにも生のアドレスが残らない
    expect((await verifyCode(codeId, code)).body.error).toBe('code_expired');
    const dump = JSON.stringify(['sites', 'pages', 'codes', 'rate_events', 'mau', 'ops_log', 'revoked_sessions'].map((t) => db.rows(`SELECT * FROM ${t}`)));
    expect(dump.toLowerCase()).not.toContain(VICTIM);
  });

  it('1 つのコードは 5 回まで。6 回目は正しいコードでも通らない', async () => {
    const { codeId, code } = await sendCode();
    const left = [];
    for (let i = 0; i < 5; i++) left.push((await verifyCode(codeId, wrong(code))).body.attemptsLeft);
    expect(left).toEqual([4, 3, 2, 1, 0]);
    const r = await verifyCode(codeId, code);
    expect(r.body.result).toBeUndefined();
    expect(r.body.ok).toBe(false);
  });

  it('並列に照合を送っても 5 回を超えて試せない(回数は原子的に確保する)', async () => {
    const { codeId, code } = await sendCode();
    // アドレスごとの上限(10 回)に掛からない数で、同時に送る。D1 は本物のように待ち時間ありにする
    env.DB = slowD1(db);
    const guesses = Array.from({ length: 9 }, (_, i) => String((Number(code) + 1 + i) % 1000000).padStart(6, '0'));
    const rs = await Promise.all(guesses.map((g) => verifyCode(codeId, g)));
    expect(rs.filter((r) => r.body.error === 'code_invalid').length).toBe(5);
    expect(rs.filter((r) => r.body.error === 'too_many').length).toBe(4);
    expect((await verifyCode(codeId, code)).body.ok).toBe(false);
  });

  it('正しいコードを同時に何度送っても、セッションは 1 つだけ(コードは取り出して消す)', async () => {
    const { codeId, code } = await sendCode();
    env.DB = slowD1(db);
    const rs = await Promise.all(Array.from({ length: 4 }, () => verifyCode(codeId, code)));
    expect(rs.filter((r) => r.body.result === 'login').length).toBe(1);
  });

  it('コードを送り直させても、アドレスごとの照合は 1 時間に 10 回まで(コードをまたいで数える)', async () => {
    const codes = [];
    for (let i = 0; i < 3; i++) codes.push(await sendCode());
    for (let i = 0; i < 4; i++) await verifyCode(codes[0].codeId, wrong(codes[0].code));
    for (let i = 0; i < 4; i++) await verifyCode(codes[1].codeId, wrong(codes[1].code));
    for (let i = 0; i < 2; i++) expect((await verifyCode(codes[2].codeId, wrong(codes[2].code))).body.error).toBe('code_invalid');
    const r = await verifyCode(codes[2].codeId, codes[2].code); // 11 回目: 正しいコードでも通らない
    expect(r.status).toBe(429);
    expect(r.body.error).toBe('too_many');
  });

  it('同じアドレスへの送信は 10 分に 3 回まで(並列でも)', async () => {
    const rs = await Promise.all(Array.from({ length: 8 }, () => call('POST', '/v1/login/email', { body: { email: VICTIM } })));
    expect(rs.filter((r) => r.status === 200).length).toBe(3);
    expect(mail.length).toBe(3);
  });

  it('サイト全体の照合の失敗が上限(環境変数)を超えたら、そのサイトの照合を止める', async () => {
    env.LIMIT_CODE_FAILS_PER_SITE_HOUR = '3';
    const { codeId, code } = await sendCode();
    for (let i = 0; i < 3; i++) await verifyCode(codeId, wrong(code));
    const r = await verifyCode(codeId, code);
    expect(r.status).toBe(429);
  });

  it('別のサイトで発行したコードは使えない。サイトはホスト名から保管庫が決める', async () => {
    const { codeId, code } = await sendCode();
    expect((await verifyCode(codeId, code, { host: OTHER_HOST })).body.error).toBe('code_expired');
    expect((await call('POST', '/v1/login/email', { host: 'evil.example', body: { email: VICTIM } })).status).toBe(404);
  });

  it('Turnstile は保管庫で検証する(画面側は飛ばせない)。別のホストで解いたトークンも不可', async () => {
    env.TURNSTILE_SECRET = TURNSTILE;
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM } })).body.error).toBe('turnstile_failed');
    turnstileReply = { success: false };
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM, turnstile: 'x' } })).body.error).toBe('turnstile_failed');
    turnstileReply = { success: true, hostname: 'evil.example' };
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM, turnstile: 'x' } })).body.error).toBe('turnstile_failed');
    turnstileReply = { success: true, hostname: HOST };
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM, turnstile: 'x' } })).status).toBe(200);
    expect(mail).toHaveLength(1);
  });

  it('メールのログインを止めたサイトでは送らない。送信キーが無ければ送らない(ログにコードを出さない)', async () => {
    db.sqlite.prepare('UPDATE sites SET settings = ? WHERE id = ?').run(JSON.stringify({ ...SITE_SETTINGS, login: { email: false, google: true } }), SITE);
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM } })).body.error).toBe('login_disabled');
    db.sqlite.prepare('UPDATE sites SET settings = ? WHERE id = ?').run(JSON.stringify(SITE_SETTINGS), SITE);
    delete env.RESEND_API_KEY;
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM } })).status).toBe(200);
    expect(mail).toHaveLength(0);
    expect(log.mock.calls.flat().join(' ')).not.toMatch(/\d{6}/);
    log.mockRestore();
  });
});

describe('Google', () => {
  it('state・verifier は保管庫に置き、交換と ID トークンの検証は保管庫で行う', async () => {
    const st = await startOAuth('google', { hint: VICTIM });
    expect(st.url.origin + st.url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(st.url.searchParams.get('redirect_uri')).toBe('https://auth.kintauros.me/google/callback'); // リダイレクト先は画面側のまま(V4)
    expect(st.url.searchParams.get('code_challenge_method')).toBe('S256');
    const r = await finish('google');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ ok: true, result: 'login', method: 'google', host: HOST, next: '/app10/', pageIds: [PAGE] });
    expect(providerCalls[0].client_secret).toBe(GOOGLE_SECRET);
    expect((await renew(r.body.session.value)).body.member.label).toBe(VICTIM);
    expect((await finish('google')).body.error).toBe('invalid_state'); // state は 1 回限り
  });

  it('bind(ブラウザとの結び付け)が違えば完了できない', async () => {
    await startOAuth('google');
    expect((await finish('google', { bind: 'x'.repeat(43) })).body.error).toBe('invalid_state');
    expect((await finish('google')).body.error).toBe('invalid_state'); // 失敗した state は消える
  });

  it('攻撃者の鍵で署名した ID トークン・nonce 違い・aud 違い・期限切れは受け付けない', async () => {
    const claims = (over) => ({ iss: 'https://accounts.google.com', aud: CLIENT_ID, sub: 'g-1', email: VICTIM, email_verified: true, exp: Math.floor(Date.now() / 1000) + 600, ...over });
    const cases = [
      ({ nonce }) => signRs(attackerKey, claims({ nonce })),
      () => signRs(google, claims({ nonce: 'other-nonce' })),
      ({ nonce }) => signRs(google, claims({ nonce, aud: 'other-client' })),
      ({ nonce }) => signRs(google, claims({ nonce, exp: Math.floor(Date.now() / 1000) - 3600 })),
    ];
    for (const make of cases) {
      idTokenFor = make;
      await startOAuth('google');
      const r = await finish('google');
      expect(r.body.ok).toBe(false);
      expect(r.body.error).toBe('google_failed');
      expect(r.body.session).toBeUndefined();
    }
  });

  it('アドレスを確認できないアカウント(Workspace で未確認)は受け付けない', async () => {
    idTokenFor = async ({ nonce }) => signRs(google, { iss: 'https://accounts.google.com', aud: CLIENT_ID, sub: 'g-2', email: 'victim@corp.example', email_verified: false, hd: 'corp.example', nonce, exp: Math.floor(Date.now() / 1000) + 600 });
    await startOAuth('google');
    const r = await finish('google');
    expect(r.body).toMatchObject({ ok: false, error: 'google_unverified', email: 'victim@corp.example', host: HOST });
  });

  it('画面側が自分でコードを交換しようとしても verifier もシークレットも無い(start の応答に含まれない)', async () => {
    const st = await startOAuth('google');
    expect(Object.keys(st.r.body).sort()).toEqual(['bind', 'ok', 'url']);
    expect(st.r.text).not.toContain(GOOGLE_SECRET);
  });
});

describe('LINE', () => {
  beforeEach(async () => {
    const dek = await newWrappedDek(env);
    db.sqlite.prepare('UPDATE sites SET line_channel_id = ?, line_secret_enc = ?, dek_wrapped = ? WHERE id = ?').run(LINE_CHANNEL, await encryptSecret(env, dek, LINE_SECRET), dek, SITE);
    idTokenFor = async ({ nonce }) => signIdTokenForTest({ channelSecret: LINE_SECRET, claims: { iss: 'https://access.line.me', aud: LINE_CHANNEL, sub: LINE_ID, name: 'ビクティム', nonce, exp: Math.floor(Date.now() / 1000) + 600 } });
  });

  it('契約者のチャネルで交換・検証し、LINE 連携 ID で照合してセッションを返す', async () => {
    const st = await startOAuth('line');
    expect(st.url.searchParams.get('client_id')).toBe(LINE_CHANNEL);
    expect(st.url.searchParams.get('redirect_uri')).toBe('https://auth.kintauros.me/line/callback');
    const r = await finish('line');
    expect(r.body).toMatchObject({ ok: true, result: 'login', method: 'line', pageIds: [PAGE], member: { kind: 'line', label: 'LINE: ビクティム' } });
    expect(providerCalls[0].client_secret).toBe(LINE_SECRET);
    expect((await renew(r.body.session.value)).body.member.kind).toBe('line');
  });

  it('チャネルシークレットを知らない者が作った ID トークンは受け付けない', async () => {
    idTokenFor = async ({ nonce }) => signIdTokenForTest({ channelSecret: 'attacker0123456789attacker012345', claims: { iss: 'https://access.line.me', aud: LINE_CHANNEL, sub: LINE_ID, nonce, exp: Math.floor(Date.now() / 1000) + 600 } });
    await startOAuth('line');
    expect((await finish('line')).body).toMatchObject({ ok: false, error: 'line_failed' });
  });

  it('Google で始めた state で LINE を完了できない(提供元を取り違えない)', async () => {
    await startOAuth('google');
    expect((await finish('line')).body.error).toBe('invalid_state');
  });
});

describe('セッション(画面側が乗っ取られても他人のセッションを作れない)', () => {
  const loginVictim = async () => {
    const { codeId, code } = await sendCode();
    return (await verifyCode(codeId, code)).body.session.value;
  };
  const payloadOf = (value) => JSON.parse(Buffer.from(value.split('.')[0], 'base64url').toString());
  const withPayload = (value, change) => `${Buffer.from(JSON.stringify({ ...payloadOf(value), ...change })).toString('base64url')}.${value.split('.')[1]}`;

  it('別の鍵で署名した値は受け付けない(画面側の鍵・保管庫の KEK で作ったものも)', async () => {
    const site = { id: SITE, session_epoch: 1, settings: SITE_SETTINGS };
    const frontEnv = { ...env, VAULT_SESSION_KEY: KEK() }; // 画面側や攻撃者が持てる鍵
    const forged = (await issueSession(frontEnv, site, { ident: { kind: 'email', id: VICTIM }, method: 'email' })).value;
    expect((await renew(forged)).status).toBe(401);
    const real = await loginVictim();
    const kekSigned = await sign(env, payloadOf(real), SESSION_INFO.session); // KEK 由来の鍵(セッションの鍵とは別)
    expect((await renew(kekSigned)).status).toBe(401);
    expect((await call('GET', '/v1/me/pages', { session: forged })).status).toBe(401);
  });

  it('中身を書き換えた値(本人・サイト・世代・期限)は受け付けない', async () => {
    const real = await loginVictim();
    expect((await renew(real)).status).toBe(200);
    for (const change of [{ e: STRANGER }, { k: 'line', e: LINE_ID }, { s: OTHER_SITE }, { ep: 2 }, { exp: payloadOf(real).exp + 1 }, { m: 'google' }]) {
      expect((await renew(withPayload(real, change))).status).toBe(401);
    }
    expect((await renew(`${real.split('.')[0]}.${'A'.repeat(43)}`)).status).toBe(401);
    expect((await renew('')).status).toBe(401);
  });

  it('期限切れ・一斉ログアウト後(世代違い)・別のサイトでは受け付けない', async () => {
    const site = { id: SITE, session_epoch: 1, settings: SITE_SETTINGS };
    const old = (await issueSession(env, site, { ident: { kind: 'email', id: VICTIM }, method: 'email', now: Date.now() - 91 * 24 * 60 * 60 * 1000 })).value;
    expect((await renew(old)).status).toBe(401);
    const real = await loginVictim();
    expect((await renew(real, OTHER_HOST)).status).toBe(401);
    db.sqlite.prepare('UPDATE sites SET session_epoch = session_epoch + 1 WHERE id = ?').run(SITE);
    expect((await renew(real)).status).toBe(401);
  });

  it('1 日以上前のセッションは延長する(sid は同じ)。ログアウトすると延長した写しも無効になる', async () => {
    const site = { id: SITE, session_epoch: 1, settings: SITE_SETTINGS };
    const old = (await issueSession(env, site, { ident: { kind: 'email', id: VICTIM }, method: 'email', now: Date.now() - 2 * 24 * 60 * 60 * 1000 })).value;
    const r = await renew(old);
    expect(r.body.renewed.value).toBeTruthy();
    const fresh = r.body.renewed.value;
    expect(payloadOf(fresh).sid).toBe(payloadOf(old).sid);
    expect(payloadOf(fresh).exp).toBeGreaterThan(payloadOf(old).exp);
    expect((await call('POST', '/v1/logout', { session: old })).body).toEqual({ ok: true });
    expect((await renew(old)).status).toBe(401);
    expect((await renew(fresh)).status).toBe(401);
    expect((await call('POST', '/v1/logout', { session: 'garbage' })).body).toEqual({ ok: true });
  });

  it('本人が入れるページ(あわせて確認するページ)を保管庫が照合して返す', async () => {
    const real = await loginVictim();
    const r = await call('GET', '/v1/me/pages?next=/app10/', { session: real });
    expect(r.body).toMatchObject({ ok: true, pageIds: [PAGE], pages: [{ id: PAGE, slug: 'app10', name: 'ご契約' }] });
    // 照合のクエリは保管庫が本人の識別子から組み立てる(画面側の入力は入らない)
    expect(kintone.calls.filter((c) => c.method === 'GET').every((c) => c.query.startsWith('(メール = "victim@gmail.com" or メール like "victim@gmail.com")'))).toBe(true);
  });

  it('本人確認を経ずにセッションを返す経路が無い(任意の内容で全部の /v1 を呼んでも)', async () => {
    const body = { email: VICTIM, ident: { kind: 'email', id: VICTIM }, kind: 'email', id: VICTIM, c: 'AAAAAAAAAAAAAAAA', code: '000000', state: `${'A'.repeat(16)}.${'B'.repeat(32)}`, bind: 'C'.repeat(43), method: 'email', session: { e: VICTIM }, verified: true, token: `${'A'.repeat(40)}.${'B'.repeat(43)}`, ticket: `${'A'.repeat(16)}.${'B'.repeat(32)}`, values: { メール: VICTIM } };
    const paths = ['/v1/site', '/v1/login/email', '/v1/login/email/code?c=AAAAAAAAAAAAAAAA', '/v1/login/email/verify', '/v1/login/google/start', '/v1/login/line/start', '/v1/login/google/finish', '/v1/login/line/finish', '/v1/session/renew', '/v1/logout', '/v1/me/pages', '/v1/session', '/v1/login', '/v1/login/session',
      // P3: 自己登録・LINE の連携・データ(本人確認の結果のトークン・引換券が無ければセッションを返さない)
      '/v1/signup', '/v1/signup/form', '/v1/line/link', '/v1/line/connect', '/v1/pages/app10/records', '/v1/pages/app10/records/5', '/v1/pages/app10/records/5/save', '/v1/pages/app10/records/5/rows', '/v1/pages/app10/files'];
    for (const p of paths) {
      for (const method of ['GET', 'POST']) {
        const r = await call(method, p, { body: method === 'POST' ? body : undefined });
        expect(r.body && r.body.session, `${method} ${p}`).toBeFalsy();
        expect(r.body && r.body.result, `${method} ${p}`).toBeFalsy();
      }
    }
  });
});

describe('/v1 の入口', () => {
  it('画面側との共有の鍵が無い・違えば 401、保管庫に鍵が未設定なら 503(本番で有効にするまで閉じている)', async () => {
    expect((await call('GET', '/v1/site', { frontKey: null })).status).toBe(401);
    expect((await call('GET', '/v1/site', { frontKey: 'wrong-key-wrong-key-wrong-key-wrong' })).status).toBe(401);
    const saved = env.VAULT_FRONT_KEY;
    delete env.VAULT_FRONT_KEY;
    expect((await call('GET', '/v1/site', { frontKey: saved })).body.error).toBe('front_key_not_configured');
    env.VAULT_FRONT_KEY = saved;
    delete env.VAULT_SESSION_KEY;
    expect((await call('GET', '/v1/site')).body.error).toBe('session_key_not_configured');
  });

  it('サイトの表示用の情報(秘密なし)。停止したサイトは 403', async () => {
    const r = await call('GET', '/v1/site');
    expect(r.body.site).toMatchObject({ slug: 'sample', name: '本物の会社', login: { email: true, google: true, line: false }, signup: false });
    expect(r.headers.get('Cache-Control')).toBe('no-store');
    db.sqlite.prepare("UPDATE sites SET status = 'suspended' WHERE id = ?").run(SITE);
    expect((await call('GET', '/v1/site')).status).toBe(403);
    expect((await call('POST', '/v1/login/email', { body: { email: VICTIM } })).status).toBe(403);
  });
});
