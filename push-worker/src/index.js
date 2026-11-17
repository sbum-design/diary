// Diary Book — 휴식 타이머 푸시 알림 서버
// 앱이 "N초 뒤에 알려줘"라고 맡기면, 시간이 됐을 때 아이폰으로 Web Push 알림을 보냅니다.
// 기기마다 Durable Object 1개가 예약 1건을 들고 있고, 알람(alarm)으로 정확한 시각에 깨어납니다.
// VAPID 키는 처음 실행할 때 서버가 스스로 만들어 저장합니다(따로 넣을 비밀값 없음).
import { DurableObject } from 'cloudflare:workers';

const te = new TextEncoder();
const b64u = buf => { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const ub64 = s => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
// RFC 8291 (aes128gcm) 메시지 암호화
async function encrypt(sub, text) {
  const uaPub = ub64(sub.keys.p256dh), auth = ub64(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, secret, concat(te.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(te.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array(4); new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
// RFC 8292 VAPID 서명
async function vapid(endpoint, keys, subject) {
  const enc = o => b64u(te.encode(JSON.stringify(o)));
  const unsigned = enc({ typ: 'JWT', alg: 'ES256' }) + '.' + enc({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject });
  const k = await crypto.subtle.importKey('jwk', keys.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k, te.encode(unsigned));
  return `vapid t=${unsigned}.${b64u(sig)}, k=${keys.pub}`;
}
async function sendPush(sub, data, keys, subject) {
  const body = await encrypt(sub, JSON.stringify(data));
  const r = await fetch(sub.endpoint, {
    method: 'POST', body,
    headers: { TTL: '300', Urgency: 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', Authorization: await vapid(sub.endpoint, keys, subject) },
  });
  return r.status;
}
const clip = (s, n) => String(s == null ? '' : s).slice(0, n);
const subOk = s => s && typeof s.endpoint === 'string' && /^https:\/\//.test(s.endpoint) && s.keys && s.keys.p256dh && s.keys.auth;

export class Timer extends DurableObject {
  async keys() {
    let k = await this.ctx.storage.get('vapid');
    if (!k) {
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      k = { jwk: await crypto.subtle.exportKey('jwk', kp.privateKey), pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)) };
      await this.ctx.storage.put('vapid', k);
    }
    return k;
  }
  async schedule(job) { await this.ctx.storage.put('job', job); await this.ctx.storage.setAlarm(job.at); return job.at; }
  async cancel() { await this.ctx.storage.delete('job'); await this.ctx.storage.deleteAlarm(); return true; }
  async sendNow(job) { return this.deliver(job); }
  async deliver(job) {
    const keys = await this.env.TIMER.get(this.env.TIMER.idFromName('__vapid')).keys();
    return sendPush(job.sub, job.data, keys, job.subject);
  }
  async alarm() {
    const job = await this.ctx.storage.get('job');
    if (!job) return;
    await this.ctx.storage.delete('job');
    try { await this.deliver(job); } catch (e) { console.log('push failed', e && e.message); }
  }
}

export default {
  async fetch(req, env) {
    const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
    const origin = req.headers.get('Origin') || '';
    const okOrigin = allowed.includes(origin);
    const cors = { 'Access-Control-Allow-Origin': okOrigin ? origin : (allowed[0] || '*'), 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400', Vary: 'Origin' };
    const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8' } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const url = new URL(req.url);
    const stub = name => env.TIMER.get(env.TIMER.idFromName(name));
    if (url.pathname === '/' || url.pathname === '') return json({ ok: true, service: 'diary-push', message: 'Diary Book 휴식 알림 서버가 동작 중입니다.' });
    if (url.pathname === '/vapid') return json({ publicKey: (await stub('__vapid').keys()).pub });
    if (req.method !== 'POST') return json({ error: 'method' }, 405);
    if (!okOrigin) return json({ error: 'origin not allowed', origin }, 403);
    let b; try { b = await req.json(); } catch (e) { return json({ error: 'json' }, 400); }
    if (!subOk(b.sub)) return json({ error: 'subscription' }, 400);
    const id = await crypto.subtle.digest('SHA-256', te.encode(b.sub.endpoint));
    const me = stub('sub:' + b64u(id));
    const subject = (allowed[0] && /^https:/.test(allowed[0])) ? allowed[0] + '/' : 'mailto:diary-book@users.noreply.github.com';
    const data = { title: clip(b.title || 'Diary Book', 80), body: clip(b.body, 200), tag: clip(b.tag || 'diary', 40), url: clip(b.url || '', 300) };
    if (url.pathname === '/schedule') {
      const now = Date.now(), at = Math.min(Math.max(Number(b.at) || now, now + 500), now + 6 * 3600 * 1000);
      return json({ ok: true, at: await me.schedule({ sub: b.sub, at, data, subject }) });
    }
    if (url.pathname === '/cancel') { await me.cancel(); return json({ ok: true }); }
    if (url.pathname === '/test') { const st = await me.sendNow({ sub: b.sub, data, subject }); return json({ ok: st >= 200 && st < 300, status: st }, st >= 200 && st < 300 ? 200 : 502); }
    return json({ error: 'not found' }, 404);
  },
};
