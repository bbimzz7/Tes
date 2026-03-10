// GET /api/checkkey?key=XXXX&hwid=YYYY&username=ZZZZ
// Bind HWID ke key (pertama kali), cek HWID + username match selanjutnya
// Returns { valid: true/false, reason?, expires?, hwid? }

const GITHUB_TOKEN   = process.env.GITHUB_TOKEN;
const GITHUB_REPO    = process.env.GITHUB_REPO;
const GITHUB_FILE    = process.env.GITHUB_FILE;
const BLACKLIST_FILE = process.env.GITHUB_BLACKLIST_FILE || "blacklist.json";

const KEY_REGEX = /^VH-[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$/;

// ── Rate limiter ──────────────────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT_MAX    = 10;
const RATE_LIMIT_WINDOW = 60 * 1000;

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
    if (res.status === 409) throw new Error("Konflik data");
    if (!res.ok) throw new Error("Gagal simpan ke GitHub");
}

export default async function handler(req, res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "GET") return res.status(405).json({ valid: false, reason: "Method not allowed" });

    const key      = (req.query.key      || "").trim().toUpperCase();
    const hwid     = (req.query.hwid     || "").trim();
    const username = (req.query.username || "").trim();
    const userId   = (req.query.userId   || "").trim();

    if (!key)  return res.status(400).json({ valid: false, reason: "Key tidak boleh kosong" });
    if (!hwid) return res.status(400).json({ valid: false, reason: "HWID tidak boleh kosong" });
    if (!KEY_REGEX.test(key)) return res.status(400).json({ valid: false, reason: "Format key tidak valid" });
    if (hwid.length > 128)   return res.status(400).json({ valid: false, reason: "HWID tidak valid" });

    // ── Rate limit ────────────────────────────────────────────
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || "unknown";
    if (isRateLimited(`hwid:${hwid}`) || isRateLimited(`ip:${ip}`)) {
        return res.status(429).json({ valid: false, reason: "Terlalu banyak request. Tunggu 1 menit." });
    }

    try {
        const [{ data: keys, sha: keysSha }, { data: blacklist }] = await Promise.all([
            ghGet(GITHUB_FILE),
            ghGet(BLACKLIST_FILE),
        ]);

        // ── Cek HWID blacklist ────────────────────────────────
        const bl = blacklist || {};
        if (bl[hwid]) {
            const blEntry = bl[hwid];
            const reason  = blEntry.reason || "Device kamu telah diblacklist";
            if (blEntry.expireAt) {
                if (Date.now() < new Date(blEntry.expireAt).getTime()) {
                    return res.status(403).json({ valid: false, reason: `❌ ${reason} (sampai ${blEntry.expireAt.substring(0, 10)})` });
                }
                // Blacklist expired → lanjut normal
            } else {
                return res.status(403).json({ valid: false, reason: `❌ ${reason}` });
            }
        }

        const entry = keys[key];
        if (!entry) return res.json({ valid: false, reason: "Key tidak ditemukan" });

        const now     = Date.now();
        const expires = new Date(entry.expires).getTime();
        if (now > expires) return res.json({ valid: false, reason: "Key sudah expired" });

        // ── Bind HWID (pertama kali) ──────────────────────────
        const isFirstBind = !entry.hwid;
        if (isFirstBind) {
            keys[key].hwid    = hwid;
            keys[key].boundAt = new Date().toISOString();
        } else if (entry.hwid !== hwid) {
            return res.json({ valid: false, reason: "Key sudah digunakan di device lain" });
        }

        // ── Validasi username (wajib sama jika sudah ter-bind) ─
        // Key yang dibuat via browser: username di-enforce
        // Key dari script: username opsional tapi di-update kalau ada
        if (entry.username && username) {
            if (entry.username.toLowerCase() !== username.toLowerCase()) {
                return res.json({
                    valid: false,
                    reason: `Username tidak cocok! Key ini terdaftar atas nama "${entry.username}". Username Roblox kamu harus sama.`
                });
            }
        }

        // ── Update lastUsed + username ────────────────────────
        keys[key].lastUsed = new Date().toISOString();
        if (username && keys[key].username !== username) keys[key].username = username;
        if (userId   && keys[key].userId   !== userId)   keys[key].userId   = userId;

        // ── Save dengan retry untuk handle 409 ───────────────
        let saved = false;
        let retryKeys = keys;
        let retrySha  = keysSha;
        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                await ghPut(GITHUB_FILE, retryKeys, retrySha, "checkkey update");
                saved = true;
                break;
            } catch (e) {
                if (e.message.includes("Konflik") && attempt < 3) {
                    await new Promise(r => setTimeout(r, 600 * attempt));
                    const fresh = await ghGet(GITHUB_FILE);
                    if (fresh.data[key]) {
                        fresh.data[key].lastUsed = retryKeys[key].lastUsed;
                        if (isFirstBind) {
                            fresh.data[key].hwid    = hwid;
                            fresh.data[key].boundAt = retryKeys[key].boundAt;
                        }
                        if (username) fresh.data[key].username = username;
                        if (userId)   fresh.data[key].userId   = userId;
                    }
                    retryKeys = fresh.data;
                    retrySha  = fresh.sha;
                } else {
                    throw e;
                }
            }
        }

        if (!saved) {
            console.warn("[checkkey] Gagal simpan setelah 3x retry, key tetap valid");
        }

        return res.json({
            valid:    true,
            expires:  entry.expires,
            hwid,
            bound:    isFirstBind,
            username: keys[key].username || null,
        });

    } catch (e) {
        console.error("[checkkey] Error:", e.message);
        return res.status(500).json({ valid: false, reason: "Server error, coba lagi" });
    }
}
