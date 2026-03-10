// /api/dashboard.js
const GITHUB_TOKEN   = process.env.GITHUB_TOKEN;
const GITHUB_REPO    = process.env.GITHUB_REPO;
const GITHUB_FILE    = process.env.GITHUB_FILE;
const LOG_FILE       = process.env.GITHUB_LOG_FILE      || "logs.json";
const CONFIG_FILE    = process.env.GITHUB_CONFIG_FILE   || "config.json";
const BLACKLIST_FILE = process.env.GITHUB_BLACKLIST_FILE || "blacklist.json";
const ADMIN_SECRET   = process.env.ADMIN_SECRET;

import crypto from "crypto";


// ── Timezone WIB (UTC+7) helpers ─────────────────────────
function toWIB(date) {
    // Tambah 7 jam ke UTC
    return new Date(date.getTime() + 7 * 60 * 60 * 1000);
}
function todayWIB() {
    return toWIB(new Date()).toISOString().substring(0, 10);
}
function nowISOWIB() {
    return toWIB(new Date()).toISOString().replace('T', ' ').substring(0, 19) + ' WIB';
}
// ── GitHub helpers ────────────────────────────────────────────
async function ghGet(file) {
    const res = await fetch(
        `https://api.github.com/repos/${GITHUB_REPO}/contents/${file}`,
        { headers: { Authorization: `token ${GITHUB_TOKEN}`, "User-Agent": "vh-key-api", "Cache-Control": "no-cache" } }
    );
    if (!res.ok) return { data: file === LOG_FILE ? [] : {}, sha: null };
    const json = await res.json();
    const content = JSON.parse(Buffer.from(json.content, "base64").toString("utf8"));
    return { data: content, sha: json.sha };
}

async function ghPut(file, data, sha, message) {
    const content = Buffer.from(JSON.stringify(data, null, 2)).toString("base64");
    const body = { message, content };
    if (sha) body.sha = sha;
    const res = await fetch(
        `https://api.github.com/repos/${GITHUB_REPO}/contents/${file}`,
        {
            method: "PUT",
            headers: { Authorization: `token ${GITHUB_TOKEN}`, "Content-Type": "application/json", "User-Agent": "vh-key-api" },
            body: JSON.stringify(body),
        }
    );
    if (res.status === 409) throw new Error("Konflik data, coba lagi");
    if (!res.ok) throw new Error("Gagal simpan ke GitHub");
    return true;
}

function generateKey() {
    const part = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `VH-${part()}-${part()}-${part()}`;
}

async function addLog(action, detail) {
    try {
        const { data: logs, sha } = await ghGet(LOG_FILE);
        const arr = Array.isArray(logs) ? logs : [];
        arr.unshift({ ts: new Date().toISOString(), action, detail });
        await ghPut(LOG_FILE, arr.slice(0, 200), sha, "add log");
    } catch(e) { console.error("[log]", e.message); }
}

function authOk(secret) {
    if (!secret || !ADMIN_SECRET) return false;
    try {
        const a = Buffer.from(secret.padEnd(64).slice(0, 64));
        const b = Buffer.from(ADMIN_SECRET.padEnd(64).slice(0, 64));
        return crypto.timingSafeEqual(a, b);
    } catch { return false; }
}

export default async function handler(req, res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.status(200).end();

    // ── Public stats (no auth) ───────────────────────────────
    const action0 = req.method === "GET" ? req.query.action : (req.body || {}).action;
    if (action0 === "publicstats") {
        try {
            const [{ data: keys }, { data: config }] = await Promise.all([ghGet(GITHUB_FILE), ghGet(CONFIG_FILE)]);
            const now2 = Date.now();
            const active = Object.values(keys).filter(v => new Date(v.expires).getTime() > now2).length;
            const maxTotal = (config && config.maxTotal) || 0;
            return res.json({ active, maxTotal });
        } catch(e) { return res.json({ active: 0, maxTotal: 0 }); }
    }

    const secret = req.method === "GET" ? req.query.secret : (req.body || {}).secret;
    if (!authOk(secret)) return res.status(401).json({ error: "Unauthorized" });

    const action = req.method === "GET" ? req.query.action : (req.body || {}).action;

    try {
        const now   = Date.now();
        const today = todayWIB();

        // ── LIST ──────────────────────────────────────────────
        if (action === "list") {
            const [{ data: keys }, { data: config }, { data: blacklist }] = await Promise.all([
                ghGet(GITHUB_FILE),
                ghGet(CONFIG_FILE),
                ghGet(BLACKLIST_FILE),
            ]);
            const bl2 = blacklist || {};
            const list = Object.entries(keys).map(([k, v]) => ({
                key:         k,
                expires:     v.expires,
                expired:     new Date(v.expires).getTime() < now,
                hwid:        v.hwid        || null,
                browserHwid: v.browserHwid || null,
                username:    v.username    || null,
                userId:      v.userId      || null,
                source:      v.source      || "script",
                boundAt:     v.boundAt     || null,
                createdAt:   v.createdAt   || null,
                lastUsed:    v.lastUsed    || null,
                blacklisted: !!(bl2[v.hwid] || (v.browserHwid && bl2[v.browserHwid])),
            }));
            const total       = list.length;
            const active      = list.filter(x => !x.expired).length;
            const expired     = list.filter(x => x.expired).length;
            const bound       = list.filter(x => x.hwid).length;
            const todayCount  = list.filter(x => (x.createdAt||"").startsWith(today)).length;
            return res.json({ keys: list, stats: { total, active, expired, bound, todayCount }, config });
        }

        // ── GET CONFIG ────────────────────────────────────────
        if (action === "getconfig") {
            const { data: config } = await ghGet(CONFIG_FILE);
            return res.json({ config });
        }

        // ── SAVE CONFIG ───────────────────────────────────────
        if (action === "saveconfig") {
            const { maxPerDay, maxTotal } = req.body || {};
            const { data: config, sha } = await ghGet(CONFIG_FILE);
            config.maxPerDay = maxPerDay !== undefined ? parseInt(maxPerDay) || 0 : config.maxPerDay || 0;
            config.maxTotal  = maxTotal  !== undefined ? parseInt(maxTotal)  || 0 : config.maxTotal  || 0;
            await ghPut(CONFIG_FILE, config, sha, "update config");
            addLog("saveconfig", `maxPerDay=${config.maxPerDay}, maxTotal=${config.maxTotal}`);
            return res.json({ success: true, config });
        }

        // ── LOGS ──────────────────────────────────────────────
        if (action === "logs") {
            const { data: logs } = await ghGet(LOG_FILE);
            return res.json({ logs: Array.isArray(logs) ? logs : [] });
        }

        // ── DELETE ────────────────────────────────────────────
        if (action === "delete") {
            const key = (req.body.key || "").toUpperCase();
            const { data: keys, sha } = await ghGet(GITHUB_FILE);
            if (!keys[key]) return res.json({ error: "Key tidak ditemukan" });
            delete keys[key];
            await ghPut(GITHUB_FILE, keys, sha, "delete key");
            addLog("delete", `Key ${key} dihapus`);
            return res.json({ success: true });
        }

        // ── BULK DELETE EXPIRED ───────────────────────────────
        if (action === "bulkdelete") {
            const { data: keys, sha } = await ghGet(GITHUB_FILE);
            let count = 0;
            for (const [k, v] of Object.entries(keys)) {
                if (new Date(v.expires).getTime() < now) { delete keys[k]; count++; }
            }
            if (count > 0) await ghPut(GITHUB_FILE, keys, sha, "bulk delete expired");
            addLog("bulkdelete", `${count} key expired dihapus`);
            return res.json({ success: true, deleted: count });
        }

        // ── DELETE ALL ────────────────────────────────────────
        if (action === "deleteall") {
            const { sha } = await ghGet(GITHUB_FILE);
            await ghPut(GITHUB_FILE, {}, sha, "delete all keys");
            addLog("deleteall", "Semua key dihapus");
            return res.json({ success: true });
        }

        // ── BULK DELETE SELECTED ──────────────────────────────
        if (action === "deleteselected") {
            const selectedKeys = req.body.keys || [];
            if (!Array.isArray(selectedKeys) || selectedKeys.length === 0)
                return res.json({ error: "Tidak ada key yang dipilih" });
            const { data: keys, sha } = await ghGet(GITHUB_FILE);
            let count = 0;
            for (const k of selectedKeys) {
                if (keys[k.toUpperCase()]) { delete keys[k.toUpperCase()]; count++; }
            }
            if (count > 0) await ghPut(GITHUB_FILE, keys, sha, `delete ${count} keys`);
            addLog("deleteselected", `${count} key dihapus`);
            return res.json({ success: true, deleted: count });
        }

        // ── RESET HWID ────────────────────────────────────────
        if (action === "resethwid") {
            const key = (req.body.key || "").toUpperCase();
            const { data: keys, sha } = await ghGet(GITHUB_FILE);
            if (!keys[key]) return res.json({ error: "Key tidak ditemukan" });
            keys[key].hwid    = null;
            keys[key].boundAt = null;
            await ghPut(GITHUB_FILE, keys, sha, "reset hwid");
            addLog("resethwid", `HWID key ${key} direset`);
            return res.json({ success: true });
        }

        // ── EXTEND ────────────────────────────────────────────
        if (action === "extend") {
            const key  = (req.body.key || "").toUpperCase();
            const days = Math.min(Math.max(parseInt(req.body.days) || 1, 1), 365);
            const { data: keys, sha } = await ghGet(GITHUB_FILE);
            if (!keys[key]) return res.json({ error: "Key tidak ditemukan" });
            const base = Math.max(new Date(keys[key].expires).getTime(), now);
            keys[key].expires = new Date(base + days * 24 * 60 * 60 * 1000).toISOString();
            await ghPut(GITHUB_FILE, keys, sha, "extend key");
            addLog("extend", `Key ${key} +${days} hari`);
            return res.json({ success: true, expires: keys[key].expires });
        }

        // ── GENERATE KEY ──────────────────────────────────────
        if (action === "genkey") {
            const count      = Math.min(Math.max(parseInt(req.body.count) || 1, 1), 50);
            const expireDays = Math.min(Math.max(parseInt(req.body.expireDays) || 1, 1), 365);
            const expireMs   = expireDays * 24 * 60 * 60 * 1000;
            const expires    = new Date(now + expireMs).toISOString();
            const { data: keys, sha } = await ghGet(GITHUB_FILE);
            const generated = [];
            for (let i = 0; i < count; i++) {
                let key;
                do { key = generateKey(); } while (keys[key]);
                keys[key] = { expires, hwid: null, createdAt: new Date().toISOString(), lastUsed: null };
                generated.push(key);
            }
            await ghPut(GITHUB_FILE, keys, sha, "generate keys");
            addLog("genkey", `${count} key, ${expireDays} hari`);
            return res.json({ success: true, keys: generated, expires, expireDays });
        }

        // ── BLACKLIST HWID ────────────────────────────────────
        if (action === "blacklist") {
            const hwid      = (req.body.hwid   || "").trim();
            const reason    = (req.body.reason || "Diblacklist oleh admin").trim();
            const days      = parseInt(req.body.days) || 0; // 0 = permanent
            if (!hwid) return res.json({ error: "HWID tidak boleh kosong" });
            if (hwid.length > 128) return res.json({ error: "HWID tidak valid" });

            const { data: bl, sha } = await ghGet(BLACKLIST_FILE);
            const blObj = bl || {};
            blObj[hwid] = {
                reason,
                blacklistedAt: new Date().toISOString(),
                expireAt: days > 0 ? new Date(now + days * 24 * 60 * 60 * 1000).toISOString() : null,
                days: days || "permanent",
            };
            await ghPut(BLACKLIST_FILE, blObj, sha, `blacklist hwid${days ? ` ${days}d` : " permanent"}`);
            addLog("blacklist", `HWID ${hwid} diblacklist — ${reason}${days ? ` (${days} hari)` : " (permanent)"}`);
            return res.json({ success: true, hwid, expireAt: blObj[hwid].expireAt });
        }

        // ── UNBLACKLIST HWID ──────────────────────────────────
        if (action === "unblacklist") {
            const hwid = (req.body.hwid || "").trim();
            if (!hwid) return res.json({ error: "HWID tidak boleh kosong" });

            const { data: bl, sha } = await ghGet(BLACKLIST_FILE);
            const blObj = bl || {};
            if (!blObj[hwid]) return res.json({ error: "HWID tidak ada di blacklist" });
            delete blObj[hwid];
            await ghPut(BLACKLIST_FILE, blObj, sha, "unblacklist hwid");
            addLog("unblacklist", `HWID ${hwid} dihapus dari blacklist`);
            return res.json({ success: true });
        }

        // ── LIST BLACKLIST ────────────────────────────────────
        if (action === "listblacklist") {
            const { data: bl } = await ghGet(BLACKLIST_FILE);
            const blObj = bl || {};
            const list = Object.entries(blObj).map(([hwid, v]) => ({
                hwid,
                reason:        v.reason        || "-",
                blacklistedAt: v.blacklistedAt || null,
                expireAt:      v.expireAt      || null,
                days:          v.days          || "permanent",
                expired:       v.expireAt ? new Date(v.expireAt).getTime() < now : false,
            }));
            return res.json({ blacklist: list });
        }

        return res.status(400).json({ error: "Unknown action" });

    } catch (e) {
        console.error("[dashboard] Error:", e.message);
        return res.status(500).json({ error: "Server error: " + e.message });
    }
}
