// ===== باسورد دخول الصفحة نفسها (الطبقة الخارجية - بتمنع أي حد غريب يوصل للتطبيق أصلاً) =====
const QUEUE_USER = "alfwlt";
const QUEUE_PASS = "9917";

const AUTH_MAX_ATTEMPTS = 8;
const AUTH_LOCK_MINUTES = 15;
const LOGIN_MAX_ATTEMPTS = 6;
const LOGIN_LOCK_MINUTES = 10;
const SESSION_DAYS = 90; // مدة بقاء تسجيل الدخول على الجهاز

const SECURITY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';",
};

function withSecurityHeaders(response) {
  const newHeaders = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) newHeaders.set(k, v);
  return new Response(response.body, { status: response.status, headers: newHeaders });
}

function checkAuth(request) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Basic ")) return false;
  const decoded = atob(authHeader.slice(6));
  const sep = decoded.indexOf(":");
  const user = decoded.slice(0, sep);
  const pass = decoded.slice(sep + 1);
  return user === QUEUE_USER && pass === QUEUE_PASS;
}

function askForLogin() {
  return new Response("محتاج تسجل دخول عشان تدخل الصفحة دي.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="دور الفنيين", charset="UTF-8"',
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

async function isIpLocked(env, ip) {
  const data = await env.QUEUE_KV.get("authlock_" + ip);
  if (!data) return false;
  const rec = JSON.parse(data);
  return rec.lockUntil && Date.now() < rec.lockUntil;
}
async function recordFailedAuth(env, ip) {
  const key = "authlock_" + ip;
  const data = await env.QUEUE_KV.get(key);
  const rec = data ? JSON.parse(data) : { attempts: 0, lockUntil: null };
  rec.attempts = (rec.attempts || 0) + 1;
  if (rec.attempts >= AUTH_MAX_ATTEMPTS) {
    rec.lockUntil = Date.now() + AUTH_LOCK_MINUTES * 60000;
    rec.attempts = 0;
  }
  await env.QUEUE_KV.put(key, JSON.stringify(rec), { expirationTtl: AUTH_LOCK_MINUTES * 60 + 60 });
}
async function clearFailedAuth(env, ip) {
  await env.QUEUE_KV.delete("authlock_" + ip);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

async function getState(env) {
  const data = await env.QUEUE_KV.get("queue_state");
  return data
    ? JSON.parse(data)
    : { workers: {}, order: [], away: [], busy: [], log: [], chat: [], dms: {}, sessions: {} };
}
async function setState(env, state) {
  await env.QUEUE_KV.put("queue_state", JSON.stringify(state));
}
function addLog(state, entry) {
  state.log = state.log || [];
  state.log.unshift({ time: new Date().toISOString(), ...entry });
  if (state.log.length > 300) state.log = state.log.slice(0, 300);
}

// ===== كلمات المرور: تشفير بسيط بـ SHA-256 (متاح جاهز في بيئة الـ Worker) =====
async function hashPasswo
