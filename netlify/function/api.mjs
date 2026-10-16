import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const COLS = ["users", "products", "orders", "returns", "missingRequests", "messages"];
const PREPEND = new Set(["orders", "returns", "missingRequests"]);
const BAD_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// ---------- helpers ----------
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

const UNESC = (s) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
const ESC = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function deepEsc(v) {
  if (typeof v === "string") return ESC(UNESC(v));
  if (Array.isArray(v)) return v.map(deepEsc);
  if (v && typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v)) if (!BAD_KEYS.has(k)) o[k] = deepEsc(v[k]);
    return o;
  }
  return v;
}
const okId = (id) => (typeof id === "string" || typeof id === "number") && /^[\w-]{1,60}$/.test(String(id));
const same = (a, b) => String(a) === String(b);
const num = (x, def = 0) => (Number.isFinite(Number(x)) ? Number(x) : def);

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const eq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function hashPw(p, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(String(p), salt, 32).toString("hex") };
}
function checkPw(u, p) {
  if (u.id === "owner-1" && process.env.ADMIN_PASSWORD) return eq(p, process.env.ADMIN_PASSWORD);
  if (!u.hash || !u.salt) return false;
  const h = crypto.scryptSync(String(p), u.salt, 32);
  return crypto.timingSafeEqual(h, Buffer.from(u.hash, "hex"));
}

const secret = () => process.env.SESSION_SECRET || process.env.ADMIN_PASSWORD || "change-me-please";
function sign(id) {
  const p = Buffer.from(JSON.stringify({ id, exp: Date.now() + 30 * 864e5 })).toString("base64url");
  return p + "." + crypto.createHmac("sha256", secret()).update(p).digest("base64url");
}
function verify(t) {
  if (!t || !t.includes(".")) return null;
  const [p, s] = t.split(".");
  const good = crypto.createHmac("sha256", secret()).update(p).digest("base64url");
  if (s.length !== good.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(good))) return null;
  try {
    const d = JSON.parse(Buffer.from(p, "base64url").toString());
    return d.exp > Date.now() ? d.id : null;
  } catch { return null; }
}

// ---------- storage ----------
const store = () => getStore({ name: "b2b", consistency: "strong" });

function seed() {
  const pw = hashPw(process.env.ADMIN_PASSWORD || "123456");
  return {
    ver: 1,
    settings: { storeName: "مركز جملة قطع غيار الموبايلات", walletNumber: "01000000000", urgentFee: 50 },
    users: [{
      id: "owner-1", name: "المالك الرئيسي", shopName: "الإدارة", phone: "admin", role: "owner", status: "active",
      address: "المقر الرئيسي", gps: "30.0444, 31.2357", balance: 0, lastGpsUpdate: null, ...pw,
    }],
    products: [], orders: [], returns: [], missingRequests: [], messages: [],
  };
}
async function load() {
  let d = await store().get("db", { type: "json" });
  if (!d) { d = seed(); await store().setJSON("db", d); }
  for (const c of COLS) if (!Array.isArray(d[c])) d[c] = [];
  return d;
}
async function save(d) {
  d.ver = (d.ver || 0) + 1;
  await store().setJSON("db", d);
}

// ---------- visibility per role ----------
const strip = (u) => { const { hash, salt, ...rest } = u; return rest; };
function view(d, u) {
  const base = { settings: d.settings };
  if (u.role === "owner" || u.role === "staff") {
    return { ...base, users: d.users.map(strip), products: d.products, orders: d.orders, returns: d.returns, missingRequests: d.missingRequests, messages: d.messages };
  }
  if (u.role === "delivery") {
    const orders = d.orders.filter((o) => same(o.agentId, u.id) || o.handoverEnabled);
    const custIds = new Set(orders.map((o) => String(o.customerId)));
    const users = d.users.filter((x) => x.id === u.id || custIds.has(String(x.id))).map(strip);
    return { ...base, users, products: d.products, orders, returns: [], missingRequests: [], messages: [] };
  }
  // customer
  const orders = d.orders.filter((o) => same(o.customerId, u.id));
  const ids = new Set(orders.map((o) => String(o.id)));
  const agentIds = new Set(orders.map((o) => String(o.agentId)));
  const users = d.users.filter((x) => x.id === u.id || agentIds.has(String(x.id))).map((x) =>
    x.id === u.id ? strip(x) : { id: x.id, name: x.name, phone: x.phone, photo: x.photo, gps: x.gps, lastGpsUpdate: x.lastGpsUpdate, role: x.role, shopName: x.shopName });
  return {
    settings: { storeName: d.settings.storeName, walletNumber: d.settings.walletNumber, urgentFee: d.settings.urgentFee },
    users, products: d.products, orders,
    returns: d.returns.filter((r) => ids.has(String(r.orderId))),
    missingRequests: d.missingRequests.filter((m) => m.customer === u.shopName),
    messages: d.messages.filter((m) => same(m.customerId, u.id)),
  };
}

// ---------- applying client changes ----------
function cleanSet(f, blocked) {
  const out = {};
  for (const k of Object.keys(f || {})) if (!BAD_KEYS.has(k) && k !== "id" && !blocked.includes(k)) out[k] = f[k];
  return out;
}
function buildItems(d, items) {
  const out = [];
  for (const it of Array.isArray(items) ? items.slice(0, 100) : []) {
    const p = d.products.find((x) => same(x.id, it.productId));
    if (!p) continue;
    const qty = Math.max(1, Math.min(1000, Math.floor(num(it.qty, 1))));
    out.push({ productId: p.id, name: `${p.model} - ${p.name}`, color: ESC(UNESC(String(it.color || ""))).slice(0, 60), price: num(p.price), qty });
  }
  return out;
}
function bump(d, custId, delta) {
  const c = d.users.find((x) => same(x.id, custId));
  if (c) c.balance = Math.max(0, num(c.balance) + delta);
}

function applyOne(d, u, op) {
  const role = u.role;
  const c = op.c;
  if (c === "settings") {
    if (role !== "owner" || op.op !== "set") return false;
    const f = cleanSet(op.f, []);
    for (const k of ["storeName", "walletNumber"]) if (k in f) d.settings[k] = String(f[k]).slice(0, 120);
    if ("urgentFee" in f) d.settings.urgentFee = Math.max(0, num(f.urgentFee));
    return true;
  }
  if (!COLS.includes(c)) return false;
  const arr = d[c];
  const find = (id) => arr.find((x) => same(x.id, id));

  // ---- ADD ----
  if (op.op === "add") {
    let item = op.item;
    if (!item || typeof item !== "object" || !okId(item.id) || find(item.id)) return false;
    if (role !== "owner") item = deepEsc(item);
    else item = deepEsc(item); // owner input is escaped too: values are rendered with innerHTML
    if (c === "users") {
      if (role !== "owner" || !["staff", "delivery"].includes(item.role)) return false;
      if (d.users.some((x) => x.phone === item.phone) || !item.phone || !item.password) return false;
      Object.assign(item, hashPw(item.password));
      delete item.password;
      item.status = "active";
    } else if (role === "owner" || role === "staff") {
      // trusted team: any of these collections
    } else if (role === "customer") {
      if (c === "orders") {
        const items = buildItems(d, item.items);
        if (!items.length) return false;
        const isUrgent = !!item.isUrgent;
        const urgentFee = isUrgent ? num(d.settings.urgentFee) : 0;
        const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
        item = {
          id: item.id, customerId: u.id, customerName: u.name, shopName: u.shopName, customerPhone: u.phone,
          customerAddress: u.address, customerGps: u.gps, items, subtotal, urgentFee, isUrgent, shippingCost: 0,
          totalAmount: subtotal + urgentFee, deliveryMethod: item.deliveryMethod, paymentMethod: item.paymentMethod,
          notes: item.notes, status: "new", handoverEnabled: false, agentConfirmedPickup: false, agentPickupTime: null,
          agentId: null, agentName: null, agentPhoto: null, agentDeliveryCollectionType: null,
          customerConfirmedReceipt: false, agentConfirmedCustomerReceipt: false, walletConfirmed: false,
          createdAt: new Date().toISOString(),
        };
        bump(d, u.id, item.totalAmount);
      } else if (c === "messages") {
        item = { id: item.id, customerId: u.id, sender: u.shopName, text: item.text, time: item.time };
      } else if (c === "returns") {
        const o = d.orders.find((x) => same(x.id, item.orderId) && same(x.customerId, u.id));
        if (!o) return false;
        item = { id: item.id, orderId: o.id, customerName: u.shopName, reason: item.reason, status: "pending" };
      } else if (c === "missingRequests") {
        item = { id: item.id, customer: u.shopName, text: item.text };
      } else return false;
    } else return false;
    if (PREPEND.has(c)) arr.unshift(item); else arr.push(item);
    return true;
  }

  const cur = find(op.id);
  if (!cur) return false;

  // ---- DELETE ----
  if (op.op === "del") {
    if (c === "users") {
      if (role !== "owner" || cur.id === u.id || cur.id === "owner-1") return false;
    } else if (role !== "owner" && role !== "staff") return false;
    arr.splice(arr.indexOf(cur), 1);
    return true;
  }

  // ---- SET ----
  if (op.op !== "set") return false;
  if (c === "users") {
    if (role === "owner") {
      const f = deepEsc(cleanSet(op.f, ["role", "hash", "salt"]));
      if ("password" in f) { Object.assign(cur, hashPw(UNESC(String(f.password)))); delete f.password; }
      Object.assign(cur, f);
      return true;
    }
    if (role === "staff" && cur.role === "customer") {
      Object.assign(cur, deepEsc(cleanSet(op.f, ["role", "password", "hash", "salt", "phone"])));
      return true;
    }
    if (role === "delivery") {
      if (cur.id === u.id) { Object.assign(cur, pick(op.f, ["gps", "lastGpsUpdate"])); return true; }
      const mine = d.orders.some((o) => same(o.agentId, u.id) && same(o.customerId, cur.id));
      if (cur.role === "customer" && mine && "balance" in (op.f || {})) { cur.balance = Math.max(0, num(op.f.balance)); return true; }
    }
    return false;
  }
  if (c === "orders") {
    if (role === "owner" || role === "staff") { Object.assign(cur, deepEsc(cleanSet(op.f, ["customerId"]))); return true; }
    if (role === "delivery") {
      if (!same(cur.agentId, u.id)) return false;
      Object.assign(cur, deepEsc(cleanSet(op.f, ["customerId", "agentId"])));
      return true;
    }
    if (role === "customer" && same(cur.customerId, u.id)) {
      const f = op.f || {};
      if ("deliveryMethod" in f) cur.deliveryMethod = deepEsc(f.deliveryMethod);
      if (f.customerConfirmedReceipt === true) {
        cur.customerConfirmedReceipt = true;
        if (cur.agentConfirmedCustomerReceipt) cur.status = "delivered";
      }
      if (f.status === "canceled" && cur.status !== "canceled" && cur.status !== "delivered") {
        cur.status = "canceled";
        if (!cur.walletConfirmed) bump(d, u.id, -num(cur.totalAmount));
      }
      const editable = ["new", "preparing", "waiting_agent"].includes(cur.status);
      if (editable && "items" in f && cur.status !== "canceled") {
        const items = buildItems(d, f.items);
        if (items.length) {
          const old = num(cur.totalAmount);
          cur.items = items;
          cur.isUrgent = !!f.isUrgent;
          cur.urgentFee = cur.isUrgent ? num(d.settings.urgentFee) : 0;
          cur.subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
          cur.totalAmount = cur.subtotal + cur.urgentFee + num(cur.shippingCost);
          if ("paymentMethod" in f) cur.paymentMethod = deepEsc(f.paymentMethod);
          if ("notes" in f) cur.notes = deepEsc(f.notes);
          bump(d, u.id, cur.totalAmount - old);
        }
      }
      return true;
    }
    return false;
  }
  if (role === "owner" || role === "staff") { Object.assign(cur, deepEsc(cleanSet(op.f, []))); return true; }
  return false;
}
function pick(f, keys) { const o = {}; for (const k of keys) if (f && k in f) o[k] = deepEsc(f[k]); return o; }

function applyOps(d, u, ops) {
  let changed = false;
  for (const op of (Array.isArray(ops) ? ops : []).slice(0, 300)) {
    try { if (applyOne(d, u, op || {})) changed = true; } catch { /* ignore a bad op */ }
  }
  return changed;
}

// ---------- routes ----------
export default async (req) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api/, "") || "/";
  try {
    if (route === "/login" && req.method === "POST") {
      const { user, pass } = await req.json();
      const d = await load();
      const u = d.users.find((x) => x.phone === String(user || "").trim());
      if (!u || !checkPw(u, pass || "")) return json({ error: "بيانات الدخول أو كلمة المرور غير صحيحة" }, 401);
      return json({ token: sign(u.id), me: u.id, ver: d.ver, state: view(d, u) });
    }

    if (route === "/register" && req.method === "POST") {
      const b = await req.json();
      const f = deepEsc({ name: b.name, shopName: b.shopName, phone: b.phone, address: b.address, gps: b.gps });
      for (const k of Object.keys(f)) f[k] = String(f[k] || "").trim().slice(0, 150);
      if (!f.name || !f.shopName || !f.phone || !b.password || String(b.password).length < 4) return json({ error: "البيانات ناقصة أو كلمة المرور قصيرة" }, 400);
      const d = await load();
      if (d.users.some((x) => x.phone === f.phone)) return json({ error: "رقم الموبايل مسجل بالفعل" }, 409);
      const u = { id: "cust-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex"), ...f, role: "customer", status: "pending", balance: 0, ...hashPw(b.password) };
      d.users.push(u);
      await save(d);
      return json({ token: sign(u.id), me: u.id, ver: d.ver, state: view(d, u) });
    }

    const authId = verify((req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""));
    if (!authId) return json({ error: "unauthorized" }, 401);
    const d = await load();
    const u = d.users.find((x) => x.id === authId);
    if (!u) return json({ error: "unauthorized" }, 401);

    if (route === "/state" && req.method === "GET") {
      if (url.searchParams.get("v") === String(d.ver)) return json({ unchanged: true, ver: d.ver });
      return json({ ver: d.ver, me: u.id, state: view(d, u) });
    }

    if (route === "/save" && req.method === "POST") {
      const { ops } = await req.json();
      if (applyOps(d, u, ops)) await save(d);
      const me = d.users.find((x) => x.id === u.id) || u;
      return json({ ver: d.ver, me: u.id, state: view(d, me) });
    }

    if (route === "/wipe" && req.method === "POST") {
      if (u.role !== "owner") return json({ error: "forbidden" }, 403);
      const fresh = seed();
      d.users = d.users.filter((x) => x.id === "owner-1");
      d.settings = fresh.settings;
      for (const c of COLS) if (c !== "users") d[c] = [];
      await save(d);
      return json({ ver: d.ver, me: u.id, state: view(d, u) });
    }

    return json({ error: "not found" }, 404);
  } catch (e) {
    return json({ error: "server error" }, 500);
  }
};
