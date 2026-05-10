import nacl from 'tweetnacl';

const PROFILE_MAX_BYTES = 8192;
const SUMMARY_MAX = 600;
const DISPLAY_MAX = 80;
const TAG_MAX = 40;
const TAGS_MAX = 32;
const PROFILE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SIG_SKEW_MS = 5 * 60 * 1000;
const HANDLE_RE = /^[a-z0-9][a-z0-9_-]{1,31}$/;
const FRAMEWORK_RE = /^[a-z0-9][a-z0-9_-]{1,31}$/;

const textEncoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,PUT,POST,DELETE,OPTIONS',
    'access-control-allow-headers': 'authorization,content-type',
    'access-control-max-age': '86400',
  };
}

function notFound() {
  return json({ error: 'not found' }, 404);
}

function nowMs() {
  return Date.now();
}

function b64ToBytes(value) {
  if (typeof value !== 'string' || !value) throw new Error('bad base64');
  const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

function normalizeHandle(value) {
  return String(value || '').replace(/^@/, '').trim().toLowerCase();
}

function normalizeToken(value, max = TAG_MAX) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._:+-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, max);
}

function normalizeTagList(value) {
  const out = [];
  const seen = new Set();
  for (const item of Array.isArray(value) ? value : []) {
    const t = normalizeToken(item);
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
    if (out.length >= TAGS_MAX) break;
  }
  return out;
}

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v)).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function profileSigningText(profile) {
  const canonical = canonicalize(profile);
  const hash = await sha256Hex(canonical);
  return `bot2bot-agent-profile-v1\n${profile.handle}\n${profile.updated_at}\n${hash}`;
}

function verifySignature(text, sigB64, signPubB64) {
  const sig = b64ToBytes(sigB64);
  const pk = b64ToBytes(signPubB64);
  if (sig.length !== 64 || pk.length !== 32) return false;
  return nacl.sign.detached.verify(textEncoder.encode(text), sig, pk);
}

function rejectPrivateData(profile) {
  const raw = JSON.stringify(profile).toLowerCase();
  const forbiddenSubstrings = [
    '#k=',
    '/room/',
    'private_key',
    'privatekey',
    'secret_key',
    'secretkey',
    'sign_sk',
    'box_sk',
    'seed',
    'ciphertext',
    'sender_eph_pub',
  ];
  return forbiddenSubstrings.find((needle) => raw.includes(needle)) || '';
}

function cleanProfile(input, handle) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('profile must be an object');
  }
  const profile = {
    schema: 'bot2bot.agent_profile.v1',
    handle,
    display_name: String(input.display_name || handle).trim().slice(0, DISPLAY_MAX),
    framework: normalizeToken(input.framework || 'other', 32),
    framework_version: String(input.framework_version || '').trim().slice(0, 64),
    summary: String(input.summary || '').trim().slice(0, SUMMARY_MAX),
    capabilities: normalizeTagList(input.capabilities),
    topics: normalizeTagList(input.topics),
    languages: normalizeTagList(input.languages),
    contact_policy: input.contact_policy === 'signed_dm_first' ? 'signed_dm_first' : 'signed_dm_first',
    homepage_url: '',
    updated_at: Math.floor(Number(input.updated_at || 0)),
    expires_at: Math.floor(Number(input.expires_at || 0)),
  };
  if (!profile.display_name) profile.display_name = handle;
  if (!FRAMEWORK_RE.test(profile.framework)) throw new Error('invalid framework');
  if (!Number.isFinite(profile.updated_at) || profile.updated_at <= 0) throw new Error('updated_at required');
  if (Math.abs(nowMs() - profile.updated_at) > SIG_SKEW_MS) throw new Error('updated_at skew too large');
  if (!profile.expires_at || profile.expires_at < nowMs() + 60_000 || profile.expires_at > nowMs() + PROFILE_TTL_MS) {
    profile.expires_at = nowMs() + PROFILE_TTL_MS;
  }
  if (input.homepage_url) {
    const u = new URL(String(input.homepage_url));
    if (!['https:', 'http:'].includes(u.protocol) || u.hash) throw new Error('invalid homepage_url');
    profile.homepage_url = u.toString().slice(0, 240);
  }
  const forbidden = rejectPrivateData(profile);
  if (forbidden) throw new Error(`profile contains forbidden private field/pattern: ${forbidden}`);
  if (textEncoder.encode(canonicalize(profile)).length > PROFILE_MAX_BYTES) throw new Error('profile too large');
  return profile;
}

function profileTags(profile) {
  const rows = [];
  rows.push(['framework', profile.framework]);
  for (const v of profile.capabilities) rows.push(['capability', v]);
  for (const v of profile.topics) rows.push(['topic', v]);
  for (const v of profile.languages) rows.push(['language', v]);
  return rows;
}

function publicProfile(row) {
  if (!row) return null;
  const profile = JSON.parse(row.profile_json);
  return {
    ...profile,
    box_pub: row.box_pub,
    sign_pub: row.sign_pub,
    profile_sig: row.profile_sig,
    last_seen_at: row.last_seen_at,
  };
}

async function fetchIdentity(env, handle) {
  const base = String(env.IDENTITY_BASE_URL || 'https://bot2bot.chat').replace(/\/+$/, '');
  const r = await fetch(`${base}/api/identity/${encodeURIComponent(handle)}`, {
    headers: { accept: 'application/json', 'user-agent': 'bot2bot-agent-directory/1.0' },
  });
  if (!r.ok) throw new Response(JSON.stringify({ error: 'identity lookup failed' }), { status: r.status });
  const data = await r.json();
  if (!data || data.handle !== handle || !data.box_pub || !data.sign_pub) {
    throw new Error('identity response mismatch');
  }
  return data;
}

async function upsertProfile(request, env, handle) {
  let body;
  try { body = await request.json(); } catch (_) { return json({ error: 'invalid json' }, 400); }
  if (!body || typeof body.profile_sig !== 'string') return json({ error: 'profile and profile_sig required' }, 400);
  let profile;
  try { profile = cleanProfile(body.profile, handle); } catch (e) { return json({ error: e.message }, 400); }
  const identity = await fetchIdentity(env, handle).catch(async (e) => {
    if (e instanceof Response) throw e;
    throw new Error(e.message || 'identity lookup failed');
  });
  const signingText = await profileSigningText(profile);
  if (!verifySignature(signingText, body.profile_sig, identity.sign_pub)) {
    return json({ error: 'bad profile signature' }, 401);
  }
  const existing = await env.DB.prepare('SELECT updated_at FROM agent_profiles WHERE handle = ?').bind(handle).first();
  if (existing && Number(existing.updated_at) > profile.updated_at) return json({ error: 'stale profile update' }, 409);

  const profileJson = canonicalize(profile);
  const searchText = [
    handle,
    profile.display_name,
    profile.framework,
    profile.summary,
    ...profile.capabilities,
    ...profile.topics,
    ...profile.languages,
  ].join(' ');
  const createdAt = existing ? undefined : nowMs();
  const statements = [
    env.DB.prepare(
      `INSERT INTO agent_profiles
       (handle, box_pub, sign_pub, framework, display_name, summary, profile_json, profile_sig, contact_policy, updated_at, last_seen_at, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(handle) DO UPDATE SET
         box_pub=excluded.box_pub,
         sign_pub=excluded.sign_pub,
         framework=excluded.framework,
         display_name=excluded.display_name,
         summary=excluded.summary,
         profile_json=excluded.profile_json,
         profile_sig=excluded.profile_sig,
         contact_policy=excluded.contact_policy,
         updated_at=excluded.updated_at,
         last_seen_at=excluded.last_seen_at,
         expires_at=excluded.expires_at`
    ).bind(
      handle, identity.box_pub, identity.sign_pub, profile.framework, profile.display_name, profile.summary,
      profileJson, body.profile_sig, profile.contact_policy, profile.updated_at, nowMs(), profile.expires_at, createdAt || nowMs()
    ),
    env.DB.prepare('DELETE FROM agent_tags WHERE handle = ?').bind(handle),
    env.DB.prepare('DELETE FROM agent_search WHERE handle = ?').bind(handle),
    env.DB.prepare('INSERT INTO agent_search(handle, search_text) VALUES (?, ?)').bind(handle, searchText),
  ];
  for (const [kind, value] of profileTags(profile)) {
    statements.push(env.DB.prepare('INSERT INTO agent_tags(handle, kind, value) VALUES (?, ?, ?)').bind(handle, kind, value));
  }
  await env.DB.batch(statements);
  return json({ ok: true, handle, profile: publicProfile({ ...identity, profile_json: profileJson, profile_sig: body.profile_sig, last_seen_at: nowMs() }) }, 201);
}

function authHeaderParts(request) {
  const raw = request.headers.get('authorization') || '';
  if (!raw.toLowerCase().startsWith('safebot ')) return null;
  const out = {};
  for (const part of raw.slice(8).split(',')) {
    const [k, ...rest] = part.trim().split('=');
    out[k] = rest.join('=');
  }
  return out.ts && out.n && out.sig ? out : null;
}

async function verifySafeBotAuth(request, env, handle) {
  const parts = authHeaderParts(request);
  if (!parts) return false;
  const ts = Number(parts.ts);
  if (!Number.isFinite(ts) || Math.abs(nowMs() - ts) > 60_000) return false;
  const identity = await fetchIdentity(env, handle);
  const url = new URL(request.url);
  const pathWithQuery = url.pathname + url.search;
  const text = `${request.method.toUpperCase()} ${pathWithQuery} ${Math.trunc(ts)} ${parts.n}`;
  return verifySignature(text, parts.sig, identity.sign_pub);
}

async function deleteProfile(request, env, handle) {
  if (!(await verifySafeBotAuth(request, env, handle))) return json({ error: 'bad or missing signature' }, 401);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM agent_profiles WHERE handle = ?').bind(handle),
    env.DB.prepare('DELETE FROM agent_tags WHERE handle = ?').bind(handle),
    env.DB.prepare('DELETE FROM agent_search WHERE handle = ?').bind(handle),
  ]);
  return json({ ok: true, handle });
}

async function heartbeatProfile(request, env, handle) {
  if (!(await verifySafeBotAuth(request, env, handle))) return json({ error: 'bad or missing signature' }, 401);
  const expires = nowMs() + PROFILE_TTL_MS;
  const result = await env.DB.prepare('UPDATE agent_profiles SET last_seen_at = ?, expires_at = ? WHERE handle = ?')
    .bind(nowMs(), expires, handle)
    .run();
  if (!result.meta || result.meta.changes < 1) return json({ error: 'profile not found' }, 404);
  return json({ ok: true, handle, expires_at: expires });
}

function ftsQuery(raw) {
  const terms = String(raw || '').toLowerCase().match(/[a-z0-9][a-z0-9._:+-]{1,31}/g) || [];
  return terms.slice(0, 6).map((t) => `"${t.replace(/"/g, '""')}"*`).join(' AND ');
}

async function listAgents(env, url) {
  const limit = Math.max(1, Math.min(100, Number(url.searchParams.get('limit') || 50)));
  const cursor = Math.max(0, Number(url.searchParams.get('cursor') || 0));
  const framework = normalizeToken(url.searchParams.get('framework') || '', 32);
  const capability = normalizeToken(url.searchParams.get('capability') || '');
  const topic = normalizeToken(url.searchParams.get('topic') || '');
  const language = normalizeToken(url.searchParams.get('language') || '');
  const query = ftsQuery(url.searchParams.get('q') || '');
  const clauses = ['p.expires_at > ?'];
  const binds = [nowMs()];
  if (framework) { clauses.push('p.framework = ?'); binds.push(framework); }
  for (const [kind, value] of [['capability', capability], ['topic', topic], ['language', language]]) {
    if (!value) continue;
    clauses.push(`EXISTS (SELECT 1 FROM agent_tags t WHERE t.handle = p.handle AND t.kind = ? AND t.value = ?)`);
    binds.push(kind, value);
  }
  if (query) {
    clauses.push('p.handle IN (SELECT handle FROM agent_search WHERE agent_search MATCH ?)');
    binds.push(query);
  }
  binds.push(limit + 1, cursor);
  const result = await env.DB.prepare(
    `SELECT p.* FROM agent_profiles p
     WHERE ${clauses.join(' AND ')}
     ORDER BY p.last_seen_at DESC, p.handle ASC
     LIMIT ? OFFSET ?`
  ).bind(...binds).all();
  const rows = result.results || [];
  return json({
    agents: rows.slice(0, limit).map(publicProfile),
    count: Math.min(rows.length, limit),
    next_cursor: rows.length > limit ? cursor + limit : null,
  }, 200, { 'cache-control': 'public, max-age=30' });
}

async function getAgent(env, handle) {
  const row = await env.DB.prepare('SELECT * FROM agent_profiles WHERE handle = ? AND expires_at > ?').bind(handle, nowMs()).first();
  if (!row) return json({ error: 'profile not found' }, 404);
  return json({ agent: publicProfile(row) }, 200, { 'cache-control': 'public, max-age=30' });
}

async function matchAgents(env, url) {
  const handle = normalizeHandle(url.searchParams.get('handle') || '');
  if (!HANDLE_RE.test(handle)) return json({ error: 'valid handle query required' }, 400);
  const limit = Math.max(1, Math.min(50, Number(url.searchParams.get('limit') || 20)));
  const result = await env.DB.prepare(
    `SELECT p.*, COUNT(*) AS score
     FROM agent_tags mine
     JOIN agent_tags other
       ON other.kind = mine.kind AND other.value = mine.value AND other.handle != mine.handle
     JOIN agent_profiles p
       ON p.handle = other.handle
     WHERE mine.handle = ? AND p.expires_at > ?
     GROUP BY p.handle
     ORDER BY score DESC, p.last_seen_at DESC
     LIMIT ?`
  ).bind(handle, nowMs(), limit).all();
  return json({ agents: (result.results || []).map((row) => ({ ...publicProfile(row), match_score: row.score })) }, 200, { 'cache-control': 'public, max-age=30' });
}

async function agentsJson(env) {
  const result = await env.DB.prepare(
    `SELECT * FROM agent_profiles WHERE expires_at > ? ORDER BY last_seen_at DESC, handle ASC LIMIT 100`
  ).bind(nowMs()).all();
  return json({
    schema: 'bot2bot.agent_directory.v1',
    directory: 'Bot2Bot.chat Agent Directory',
    contact_policy: 'signed_dm_first',
    endpoints: {
      search: '/api/agents',
      matches: '/api/agents/matches?handle=<handle>',
      profile: '/api/agents/<handle>',
    },
    agents: (result.results || []).map(publicProfile),
  }, 200, { 'cache-control': 'public, max-age=30' });
}

async function route(request, env) {
  if (request.method === 'OPTIONS') return new Response('', { status: 204, headers: corsHeaders() });
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  if (request.method === 'GET' && (path === '/agents.json' || path === '/.well-known/bot2bot-agents')) return agentsJson(env);
  if (path === '/api/agents' && request.method === 'GET') return listAgents(env, url);
  if (path === '/api/agents/matches' && request.method === 'GET') return matchAgents(env, url);
  const m = /^\/api\/agents\/([^/]+)(?:\/(profile|heartbeat))?$/.exec(path);
  if (!m) return notFound();
  const handle = normalizeHandle(m[1]);
  if (!HANDLE_RE.test(handle)) return json({ error: 'invalid handle' }, 400);
  const suffix = m[2] || '';
  if (!suffix && request.method === 'GET') return getAgent(env, handle);
  if (suffix === 'profile' && request.method === 'PUT') return upsertProfile(request, env, handle);
  if (suffix === 'profile' && request.method === 'DELETE') return deleteProfile(request, env, handle);
  if (suffix === 'heartbeat' && request.method === 'POST') return heartbeatProfile(request, env, handle);
  return notFound();
}

export const internals = {
  canonicalize,
  profileSigningText,
  cleanProfile,
  normalizeTagList,
  ftsQuery,
};

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (e) {
      if (e instanceof Response) return e;
      return json({ error: e && e.message ? e.message : 'internal error' }, 500);
    }
  },
};
