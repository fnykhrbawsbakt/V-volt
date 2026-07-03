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
async function hashPassword(pw) {
  const data = new TextEncoder().encode("fanniqueue_salt_" + pw);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function genPassword() {
  // كلمة مرور بسيطة يقدر الفني يتذكرها: 6 أرقام
  return String(Math.floor(100000 + Math.random() * 900000));
}
function genToken() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function normalizePhone(phone) {
  return (phone || "").replace(/[^0-9]/g, "");
}

// يرجع { workerId, worker } من التوكن المرسل، أو null لو التوكن غير صالح/منتهي
function resolveSession(state, token) {
  if (!token) return null;
  const session = (state.sessions || {})[token];
  if (!session) return null;
  if (Date.now() > session.expires) return null;
  const worker = state.workers[session.workerId];
  if (!worker) return null;
  return { workerId: session.workerId, worker };
}

async function isLoginLocked(env, phone) {
  const data = await env.QUEUE_KV.get("loginlock_" + phone);
  if (!data) return false;
  const rec = JSON.parse(data);
  return rec.lockUntil && Date.now() < rec.lockUntil;
}
async function recordFailedLogin(env, phone) {
  const key = "loginlock_" + phone;
  const data = await env.QUEUE_KV.get(key);
  const rec = data ? JSON.parse(data) : { attempts: 0, lockUntil: null };
  rec.attempts = (rec.attempts || 0) + 1;
  if (rec.attempts >= LOGIN_MAX_ATTEMPTS) {
    rec.lockUntil = Date.now() + LOGIN_LOCK_MINUTES * 60000;
    rec.attempts = 0;
  }
  await env.QUEUE_KV.put(key, JSON.stringify(rec), { expirationTtl: LOGIN_LOCK_MINUTES * 60 + 60 });
}
async function clearFailedLogin(env, phone) {
  await env.QUEUE_KV.delete("loginlock_" + phone);
}

export default {
  async fetch(request, env) {
    const response = await handleRequest(request, env);
    return withSecurityHeaders(response);
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const origin = url.origin;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const isProtected =
    url.pathname === "/" || url.pathname === "/index.html" || url.pathname.startsWith("/api/queue");

  if (isProtected) {
    if (await isIpLocked(env, ip)) {
      return new Response("محاولات كتير غلط. جرب تاني بعد شوية.", {
        status: 429,
        headers: { "Content-Type": "text/plain; charset=utf-8", "Retry-After": String(AUTH_LOCK_MINUTES * 60) },
      });
    }
    if (!checkAuth(request)) {
      await recordFailedAuth(env, ip);
      return askForLogin();
    }
    await clearFailedAuth(env, ip);
  }

  // ===== قراءة الحالة الحالية (بيانات عامة، بدون كلمات المرور) =====
  if (url.pathname === "/api/queue" && request.method === "GET") {
    const state = await getState(env);
    const safeWorkers = {};
    for (const id of Object.keys(state.workers)) {
      const { passwordHash, ...rest } = state.workers[id];
      safeWorkers[id] = rest;
    }
    return json({ ...state, workers: safeWorkers, sessions: undefined });
  }

  // ===== تسجيل الدخول الشخصي =====
  if (url.pathname === "/api/queue/login" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ ok: false, error: "بيانات غير صالحة" }, 400);
    }
    const phone = normalizePhone(body.phone);
    if (!phone) return json({ ok: false, error: "اكتب رقم الجوال" }, 400);
    if (await isLoginLocked(env, phone)) {
      return json({ ok: false, error: `محاولات كتير غلط. جرب بعد ${LOGIN_LOCK_MINUTES} دقايق` }, 429);
    }
    const state = await getState(env);
    const entry = Object.entries(state.workers).find(([, w]) => w.phone === phone);
    if (!entry) {
      await recordFailedLogin(env, phone);
      return json({ ok: false, error: "رقم الجوال أو كلمة المرور غلط" }, 401);
    }
    const [workerId, worker] = entry;
    const hash = await hashPassword(body.password || "");
    if (hash !== worker.passwordHash) {
      await recordFailedLogin(env, phone);
      return json({ ok: false, error: "رقم الجوال أو كلمة المرور غلط" }, 401);
    }
    await clearFailedLogin(env, phone);
    const token = genToken();
    state.sessions = state.sessions || {};
    state.sessions[token] = { workerId, expires: Date.now() + SESSION_DAYS * 86400000 };
    await setState(env, state);
    return json({ ok: true, token, workerId, name: worker.name, role: worker.role });
  }

  if (url.pathname === "/api/queue/logout" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      body = {};
    }
    const state = await getState(env);
    if (state.sessions && body.token) delete state.sessions[body.token];
    await setState(env, state);
    return json({ ok: true });
  }

  // ===== تنفيذ إجراء =====
  if (url.pathname === "/api/queue/action" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ ok: false, error: "بيانات غير صالحة" }, 400);
    }

    const state = await getState(env);
    const { type } = body;

    // إجراءات إدارية (مسموحة بباسورد الصفحة بس، مش محتاجة جلسة فني)
    if (type === "add") {
      const id = "w_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      const name = (body.name || "").trim();
      const role = body.role || "عام";
      const phone = normalizePhone(body.phone);
      if (!name) return json({ ok: false, error: "الاسم مطلوب" }, 400);
      if (!phone || phone.length < 8) return json({ ok: false, error: "رقم جوال غير صالح" }, 400);
      if (Object.values(state.workers).some((w) => w.phone === phone)) {
        return json({ ok: false, error: "رقم الجوال ده مسجل بالفعل لفني تاني" }, 400);
      }
      const password = genPassword();
      state.workers[id] = { name, role, phone, passwordHash: await hashPassword(password) };
      state.order.push(id);
      addLog(state, { action: "add", workerName: name, workerRole: role });
      await setState(env, state);
      return json({ ok: true, state: sanitize(state), generatedPassword: password });
    }

    if (type === "remove") {
      const w = state.workers[body.id];
      if (w) {
        delete state.workers[body.id];
        state.order = state.order.filter((x) => x !== body.id);
        state.away = (state.away || []).filter((a) => a.id !== body.id);
        state.busy = (state.busy || []).filter((b) => b.id !== body.id);
        if (state.sessions) {
          for (const t of Object.keys(state.sessions)) {
            if (state.sessions[t].workerId === body.id) delete state.sessions[t];
          }
        }
        addLog(state, { action: "remove", workerName: w.name, workerRole: w.role });
      }
      await setState(env, state);
      return json({ ok: true, state: sanitize(state) });
    }

    if (type === "reset_password") {
      const w = state.workers[body.id];
      if (!w) return json({ ok: false, error: "الفني مش موجود" }, 400);
      const newPassword = genPassword();
      w.passwordHash = await hashPassword(newPassword);
      if (state.sessions) {
        for (const t of Object.keys(state.sessions)) {
          if (state.sessions[t].workerId === body.id) delete state.sessions[t];
        }
      }
      addLog(state, { action: "reset_password", workerName: w.name, workerRole: w.role });
      await setState(env, state);
      return json({ ok: true, state: sanitize(state), generatedPassword: newPassword });
    }

    // باقي الإجراءات محتاجة جلسة فني مسجل دخول (التوكن هو اللي بيحدد الهوية، مش أي حقل بيبعته الجهاز)
    const session = resolveSession(state, body.token);
    if (!session) {
      return json({ ok: false, error: "لازم تسجل دخول تاني", needLogin: true }, 401);
    }
    const myId = session.workerId;
    const w = session.worker;

    if (type === "take") {
      const idx = state.order.indexOf(myId);
      if (idx !== -1) {
        state.order.splice(idx, 1);
        state.busy = state.busy || [];
        state.busy.push({ id: myId, since: new Date().toISOString() });
        addLog(state, { action: "took", workerName: w.name, workerRole: w.role });
      }
    } else if (type === "finish") {
      state.busy = (state.busy || []).filter((b) => b.id !== myId);
      if (!state.order.includes(myId)) {
        state.order.push(myId);
        addLog(state, { action: "finished", workerName: w.name, workerRole: w.role });
      }
    } else if (type === "leave") {
      const reason = (body.reason || "").trim();
      if (!reason) return json({ ok: false, error: "لازم تكتب اسم العميل أو السبب" }, 400);
      const idx = state.order.indexOf(myId);
      if (idx !== -1) {
        state.order.splice(idx, 1);
        state.away = state.away || [];
        state.away.push({ id: myId, since: new Date().toISOString(), reason });
        addLog(state, { action: "left", workerName: w.name, workerRole: w.role, reason });
      }
    } else if (type === "return") {
      state.away = (state.away || []).filter((a) => a.id !== myId);
      if (!state.order.includes(myId)) {
        state.order.push(myId);
        addLog(state, { action: "returned", workerName: w.name, workerRole: w.role });
      }
    } else if (type === "chat") {
      const text = (body.text || "").trim();
      if (!text) return json({ ok: false, error: "اكتب رسالة" }, 400);
      if (text.length > 500) return json({ ok: false, error: "الرسالة طويلة أوي" }, 400);
      const msgId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      const msg = { id: msgId, time: new Date().toISOString(), workerName: w.name, fromId: myId, text, reactions: {} };
      const to = body.to || "group";
      if (to === "group") {
        state.chat = state.chat || [];
        state.chat.push(msg);
        if (state.chat.length > 200) state.chat = state.chat.slice(state.chat.length - 200);
      } else {
        const other = state.workers[to];
        if (!other) return json({ ok: false, error: "الشخص مش موجود" }, 400);
        const key = [myId, to].sort().join("_");
        state.dms = state.dms || {};
        state.dms[key] = state.dms[key] || [];
        msg.toId = to;
        state.dms[key].push(msg);
        if (state.dms[key].length > 200) state.dms[key] = state.dms[key].slice(state.dms[key].length - 200);
      }
    } else if (type === "react") {
      const allowed = ["👍", "😂", "🔥", "❤️"];
      const emoji = body.emoji;
      if (!allowed.includes(emoji)) return json({ ok: false, error: "رياكشن غير مسموح" }, 400);
      let msg = null;
      if (body.thread === "group") msg = (state.chat || []).find((m) => m.id === body.msgId);
      else if (body.thread) msg = ((state.dms || {})[body.thread] || []).find((m) => m.id === body.msgId);
      if (!msg) return json({ ok: false, error: "الرسالة مش موجودة" }, 400);
      msg.reactions = msg.reactions || {};
      msg.reactions[emoji] = (msg.reactions[emoji] || 0) + 1;
    } else {
      return json({ ok: false, error: "إجراء غير معروف" }, 400);
    }

    await setState(env, state);
    return json({ ok: true, state: sanitize(state) });
  }

  return env.ASSETS.fetch(request);
}

function sanitize(state) {
  const safeWorkers = {};
  for (const id of Object.keys(state.workers)) {
    const { passwordHash, ...rest } = state.workers[id];
    safeWorkers[id] = rest;
  }
  return { ...state, workers: safeWorkers, sessions: undefined };
      }
