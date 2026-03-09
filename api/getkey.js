import crypto from "crypto";

const SECRET        = process.env.TOKEN_SECRET || process.env.ADMIN_SECRET || "fallback-secret";
const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GITHUB_REPO   = process.env.GITHUB_REPO;
const GITHUB_FILE   = process.env.GITHUB_FILE;
const CONFIG_FILE   = process.env.GITHUB_CONFIG_FILE   || "config.json";
const BLACKLIST_FILE = process.env.GITHUB_BLACKLIST_FILE || "blacklist.json";
const KEY_EXPIRE_MS = 24 * 60 * 60 * 1000;

function sign(data) {
    return crypto.createHmac("sha256", SECRET).update(data).digest("hex").substring(0, 32);
}

function verifyToken(d, s) {
    if (!d || !s) return null;
    if (sign(d) !== s) return null;
    try {
        const payload = JSON.parse(Buffer.from(d, "base64url").toString("utf8"));
        if (Date.now() > payload.exp) return null;
        return payload;
    } catch { return null; }
}

// ── In-memory rate limiter ────────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT_MAX    = 5;           // max 5 request getkey
const RATE_LIMIT_WINDOW = 60 * 1000;  // per menit

function isRateLimited(identifier) {
    const now   = Date.now();
    const entry = rateLimitMap.get(identifier);
    if (!entry || now > entry.resetAt) {
        rateLimitMap.set(identifier, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
        return false;
    }
    entry.count++;
    return entry.count > RATE_LIMIT_MAX;
}

// ── GitHub helpers ────────────────────────────────────────────
async function ghGet(file) {
    const res = await fetch(
        `https://api.github.com/repos/${GITHUB_REPO}/contents/${file}`,
        { headers: { Authorization: `token ${GITHUB_TOKEN}`, "User-Agent": "vh-key-api", "Cache-Control": "no-cache" } }
    );
    if (!res.ok) return { data: {}, sha: null };
    const json = await res.json();
    return { data: JSON.parse(Buffer.from(json.content, "base64").toString("utf8")), sha: json.sha };
}

async function ghPut(file, data, sha, message) {
    const content = Buffer.from(JSON.stringify(data, null, 2)).toString("base64");
    const body = { message, content };
    if (sha) body.sha = sha;
    const res = await fetch(
        `https://api.github.com/repos/${GITHUB_REPO}/contents/${file}`,
        { method: "PUT", headers: { Authorization: `token ${GITHUB_TOKEN}`, "Content-Type": "application/json", "User-Agent": "vh-key-api" }, body: JSON.stringify(body) }
    );
    if (res.status === 409) throw new Error("CONFLICT");
    if (!res.ok) throw new Error("Gagal simpan ke GitHub");
}

function generateKey() {
    const part = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `VH-${part()}-${part()}-${part()}`;
}

// ── Retry wrapper untuk handle 409 race condition ─────────────
async function withRetry(fn, maxAttempts = 3) {
    for (let i = 1; i <= maxAttempts; i++) {
        try {
            return await fn();
        } catch (e) {
            if (e.message === "CONFLICT" && i < maxAttempts) {
                await new Promise(r => setTimeout(r, 500 * i));
                continue;
            }
            throw e;
        }
    }
}

export default async function handler(req, res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "GET")    return res.status(405).json({ error: "Method not allowed" });

    const d         = req.query.d;
    const s         = req.query.s;
    const accept    = req.headers["accept"] || "";
    const userAgent = req.headers["user-agent"] || "";
    const isFetch   = accept.includes("application/json") || req.headers["x-requested-with"] === "XMLHttpRequest";
    const isBrowser = (userAgent.includes("Mozilla") || userAgent.includes("Chrome")) && !isFetch;

    let hwid, username, userId;

    if (d && s) {
        const payload = verifyToken(d, s);
        if (!payload) {
            if (isBrowser) return res.redirect(302, "/?expired=1");
            return res.status(401).json({ error: "Token tidak valid atau sudah expired (5 menit)" });
        }
        hwid     = payload.hwid;
        username = payload.username || "";
        userId   = payload.userId   || "";
    } else {
        if (isBrowser) return res.redirect(302, "/?error=invalid");
        hwid     = (req.query.hwid     || "").trim();
        username = (req.query.username || "").trim();
        userId   = (req.query.userId   || "").trim();
    }

    if (!hwid)             return res.status(400).json({ error: "HWID tidak boleh kosong" });
    if (hwid.length > 128) return res.status(400).json({ error: "HWID tidak valid" });

    // ── Rate limit per HWID + IP ──────────────────────────────
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || "unknown";
    if (isRateLimited(`hwid:${hwid}`) || isRateLimited(`ip:${ip}`)) {
        return res.status(429).json({ error: "Terlalu banyak request. Tunggu 1 menit." });
    }

    try {
        const now   = Date.now();
        const today = new Date().toISOString().substring(0, 10);

        // ── Load semua data paralel ───────────────────────────
        const [{ data: keys, sha: keysSha }, { data: config }, { data: blacklist }] = await Promise.all([
            ghGet(GITHUB_FILE),
            ghGet(CONFIG_FILE),
            ghGet(BLACKLIST_FILE),
        ]);

        // ── Cek blacklist HWID ────────────────────────────────
        const bl = blacklist || {};
        if (bl[hwid]) {
            const blEntry = bl[hwid];
            const reason  = blEntry.reason || "Device kamu telah diblacklist";
            if (blEntry.expireAt) {
                if (Date.now() < new Date(blEntry.expireAt).getTime()) {
                    const expDate = blEntry.expireAt.substring(0, 10);
                    return res.status(403).json({ error: `❌ ${reason} (sampai ${expDate})` });
                }
                // Blacklist expired → lanjut
            } else {
                return res.status(403).json({ error: `❌ ${reason}` });
            }
        }

        const maxPerDay  = config.maxPerDay || 0;
        const maxTotal   = config.maxTotal  || 0;
        const allKeys    = Object.values(keys);
        const todayCount = allKeys.filter(v => (v.createdAt || "").startsWith(today)).length;
        const totalActive = allKeys.filter(v => new Date(v.expires).getTime() > now).length;

        // ── HWID sudah punya key aktif → return key yang sama ─
        for (const [k, v] of Object.entries(keys)) {
            if (v.hwid === hwid && new Date(v.expires).getTime() > now) {
                let updated = false;
                if (username && v.username !== username) { keys[k].username = username; updated = true; }
                if (userId   && v.userId   !== userId)   { keys[k].userId   = userId;   updated = true; }
                if (updated) {
                    await withRetry(() => ghPut(GITHUB_FILE, keys, keysSha, "update username"));
                }
                return res.json({ key: k, expires: v.expires, reused: true });
            }
        }

        // ── Cek limit ─────────────────────────────────────────
        if (maxTotal  > 0 && totalActive >= maxTotal)  return res.status(429).json({ error: `Limit tercapai! Max ${maxTotal} key aktif.` });
        if (maxPerDay > 0 && todayCount  >= maxPerDay) return res.status(429).json({ error: `Limit harian tercapai! Max ${maxPerDay}/hari.` });

        // ── Generate key baru dengan retry untuk 409 ──────────
        let resultKey, resultExpires;

        await withRetry(async () => {
            // Re-fetch tiap retry supaya SHA selalu fresh
            const { data: freshKeys, sha: freshSha } = await ghGet(GITHUB_FILE);

            let key;
            do { key = generateKey(); } while (freshKeys[key]);

            const expires = new Date(now + KEY_EXPIRE_MS).toISOString();
            freshKeys[key] = {
                expires,
                hwid,
                username: username || null,
                userId:   userId   || null,
                createdAt: new Date().toISOString(),
                lastUsed:  null,
            };

            await ghPut(GITHUB_FILE, freshKeys, freshSha, "generate key");
            resultKey     = key;
            resultExpires = expires;
        });

        return res.json({ key: resultKey, expires: resultExpires, reused: false });

    } catch (e) {
        console.error("[getkey] Error:", e.message);
        return res.status(500).json({ error: "Server error, coba lagi" });
    }
}
