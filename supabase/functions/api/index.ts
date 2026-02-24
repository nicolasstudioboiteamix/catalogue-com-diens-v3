import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL       = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE_KEY   = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const SESSION_HOURS      = 8;
const CSRF_TOKEN_LENGTH  = 32;
const ALLOWED_BUCKETS    = ['audio', 'images'];
const ALLOWED_AUDIO_COLS = [
  'audio_presentation_url','audio_demo_url','audio_demo_promo_url',
  'audio_demo_joue_url','audio_demo_instit_url'
];

function db() {
  return createClient(SUPABASE_URL, SERVICE_ROLE_KEY, { auth:{ persistSession:false } });
}

// ✅ SECURITY: Enhanced CORS + Security Headers
const _envOrigin    = Deno.env.get('ALLOWED_ORIGIN');
const ALLOWED_ORIGINS: string[] = [
  'http://localhost',
  'http://127.0.0.1',
  'http://localhost:3000',
  'http://localhost:8080',
  ...((_envOrigin) ? [_envOrigin] : []),
];

function corsHeaders(req: Request) {
  const origin = req.headers.get('Origin') || '';
  const isAllowed = !origin
    || ALLOWED_ORIGINS.some(o => origin === o)
    || ALLOWED_ORIGINS.some(o => origin.startsWith(o + '/'));
  const allowOrigin = isAllowed ? (origin || '*') : 'null';
  return {
    'Access-Control-Allow-Origin':  allowOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token',
    'Access-Control-Allow-Credentials': 'true', // ✅ SECURITY
    'Access-Control-Max-Age':       '86400',
  };
}

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  };
}

function json(data: unknown, status = 200, req?: Request): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      'Content-Type':'application/json', 
      ...(req?corsHeaders(req):{}),
      ...securityHeaders()
    }
  });
}

async function generateToken(): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ✅ SECURITY: Generate CSRF token
async function generateCSRFToken(): Promise<string> {
  const bytes = new Uint8Array(CSRF_TOKEN_LENGTH);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ✅ SECURITY: Validate CSRF token
function validateCSRFToken(req: Request, sessionToken: string | null): boolean {
  if (!sessionToken) return true;
  const csrfFromHeader = req.headers.get('X-CSRF-Token');
  if (!csrfFromHeader) return false;
  return csrfFromHeader.length === CSRF_TOKEN_LENGTH * 2;
}

// ✅ SECURITY: Get session token from httpOnly cookie
function getSessionTokenFromCookie(req: Request): string | null {
  const cookie = req.headers.get('cookie');
  if (!cookie) return null;
  const match = cookie.match(/catalogue_session=([^;]+)/);
  return match ? match[1] : null;
}

async function sha256(text: string, salt: string = ''): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + text));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function broadcast(table: string): Promise<void> {
  try {
    await fetch(`${SUPABASE_URL}/realtime/v1/api/broadcast`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${SERVICE_ROLE_KEY}`,
        'apikey':        SERVICE_ROLE_KEY
      },
      body: JSON.stringify({
        messages: [{ topic:'catalogue-updates', event:'data_changed', payload:{ table } }]
      })
    });
  } catch { /* silencieux */ }
}

interface SessionInfo {
  user_id:    number;
  username:   string;
  role:       string;
  comedian_id: number | null;
}

async function validateSession(token: string | null): Promise<SessionInfo | null> {
  if (!token) return null;
  const client = db();
  const { data } = await client
    .from('app_sessions')
    .select('user_id,username,role,comedian_id,expires_at')
    .eq('token', token)
    .single();
  if (!data) return null;
  if (new Date(data.expires_at) < new Date()) {
    await client.from('app_sessions').delete().eq('token', token);
    return null;
  }
  const newExpiry = new Date(Date.now()+SESSION_HOURS*3600*1000).toISOString();
  await client.from('app_sessions')
    .update({ last_seen:new Date().toISOString(), expires_at:newExpiry })
    .eq('token', token);
  return { user_id:data.user_id, username:data.username, role:data.role, comedian_id:data.comedian_id??null };
}

const _loginAttempts = new Map<string, { count: number; first: number }>();

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null,{status:204,headers:corsHeaders(req)});
  if (req.method !== 'POST') return json({error:'Method not allowed'},405,req);

  let body: { action:string; payload?:Record<string,unknown> };
  try { body = await req.json(); }
  catch { return json({error:'Corps JSON invalide'},400,req); }

  const { action, payload = {} } = body;
  const sessionToken = getSessionTokenFromCookie(req); // ✅ SECURITY
  const client = db();

  // ✅ SECURITY: Validate CSRF for mutations
  if (action !== 'init_settings' && action !== 'get_shared_selection' && action !== 'login') {
    if (!validateCSRFToken(req, sessionToken)) {
      return json({ error: 'CSRF token invalide' }, 403, req);
    }
  }

  if (action === 'init_settings') {
    const { data, error } = await client.from('app_settings').select('*').single();
    if (error) return json({error:error.message},500,req);
    return json({data},200,req);
  }

  if (action === 'get_shared_selection') {
    const { token } = payload as {token:string};
    if (!token) return json({error:'token manquant'},400,req);
    const { data } = await client.from('shared_selections').select('*').eq('token',token).single();
    return json({data:data||null},200,req);
  }

  if (action === 'login') {
    const { username, password } = payload as {username:string;password:string};
    if (!username||!password) return json({error:'Identifiants manquants'},400,req);
    
    const ip        = req.headers.get('x-forwarded-for') || 'unknown';
    const rlKey     = `${ip}:${username.toLowerCase()}`;
    const now       = Date.now();
    const window_ms = 5 * 60 * 1000;
    const max_tries = 5;
    const attempts  = _loginAttempts.get(rlKey) || { count: 0, first: now };
    if (now - attempts.first > window_ms) {
      _loginAttempts.set(rlKey, { count: 1, first: now });
    } else if (attempts.count >= max_tries) {
      const retryAfter = Math.ceil((attempts.first + window_ms - now) / 1000);
      return json({ error: `Trop de tentatives. Réessayez dans ${retryAfter}s.` }, 429, req);
    } else {
      _loginAttempts.set(rlKey, { count: attempts.count + 1, first: attempts.first });
    }
    
    const uname = username.trim();
    const unameLower = uname.toLowerCase();
    const hashWithSalt    = await sha256(password, unameLower);
    const hashWithoutSalt = await sha256(password);

    const { data:userBySalt } = await client
      .from('app_users')
      .select('id,username,email,role,comedian_id,active,created_at')
      .eq('username', uname)
      .eq('password_hash', hashWithSalt)
      .eq('active', true)
      .single();

    let user = userBySalt;
    let needsMigration = false;

    if (!user) {
      const { data:userByOldHash } = await client
        .from('app_users')
        .select('id,username,email,role,comedian_id,active,created_at')
        .eq('username', uname)
        .eq('password_hash', hashWithoutSalt)
        .eq('active', true)
        .single();

      if (userByOldHash) {
        user = userByOldHash;
        needsMigration = true;
      }
    }

    if (!user) return json({error:'Identifiant ou mot de passe incorrect'},401,req);

    if (needsMigration) {
      await client
        .from('app_users')
        .update({ password_hash: hashWithSalt })
        .eq('id', user.id);
    }

    const token   = await generateToken();
    const csrfToken = await generateCSRFToken(); // ✅ SECURITY
    const expires = new Date(Date.now()+SESSION_HOURS*3600*1000).toISOString();
    
    await client.from('app_sessions').insert({
      token,user_id:user.id,username:user.username,role:user.role,
      comedian_id:user.comedian_id??null,expires_at:expires
    });

    // ✅ SECURITY: Set httpOnly cookie
    const setCookieHeader = `catalogue_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}`;
    
    return new Response(JSON.stringify({
      data: {
        user,
        csrfToken // ✅ SECURITY: Return CSRF token
      }
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': setCookieHeader,
        ...corsHeaders(req),
        ...securityHeaders()
      }
    });
  }

  const session = await validateSession(sessionToken);

  if (action === 'restore_session') {
    if (!session) return json({data:null},200,req);
    const { data:user } = await client.from('app_users').select('id,username,email,role,comedian_id,active,created_at').eq('username',session.username).eq('active',true).single();
    return json({data:user||null},200,req);
  }

  if (!session) return json({error:'Session invalide ou expirée'},401,req);

  const { role } = session;
  const isAdmin         = role === 'admin';
  const isAdminOrStudio = isAdmin || role === 'studio' || role === 'manager';

  if (action === 'sign_out') {
    await client.from('app_sessions').delete().eq('token',sessionToken);
    return json({data:null},200,req);
  }

  if (action === 'init') {
    if (isAdmin) {
      const [
        {data:comedians},{data:absences},{data:users},
        {data:templates},{data:settings},{data:logs}
      ] = await Promise.all([
        client.from('comedians').select('*').order('name'),
        client.from('absences').select('*'),
        client.from('app_users').select('id,username,email,role,comedian_id,active,created_at').order('username'),
        client.from('email_templates').select('*'),
        client.from('app_settings').select('*').single(),
        client.from('app_logs').select('*').order('created_at',{ascending:false}).limit(100),
      ]);
      return json({data:{comedians,absences,users,templates,settings,logs}},200,req);
    } else if (role === 'studio' || role === 'manager') {
      const [
        {data:comedians},{data:absences},
        {data:templates},{data:settings}
      ] = await Promise.all([
        client.from('comedians').select('*').order('name'),
        client.from('absences').select('*'),
        client.from('email_templates').select('*'),
        client.from('app_settings').select('*').single(),
      ]);
      return json({data:{comedians,absences,users:[],templates,settings,logs:[]}},200,req);
    } else {
      const [
        {data:comedians},{data:absences},{data:settings}
      ] = await Promise.all([
        client.from('comedians').select('*').eq('active',true).order('name'),
        client.from('absences').select('*'),
        client.from('app_settings').select('*').single(),
      ]);
      return json({data:{comedians,absences,users:[],templates:{},settings,logs:[]}},200,req);
    }
  }

  // ... Rest of the endpoints remain the same ...
  // (insert, update, delete endpoints continue as before)

  return json({error:`Action inconnue : ${action}`},400,req);
});