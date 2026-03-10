import crypto from "crypto";

const SECRET = process.env.TOKEN_SECRET || process.env.ADMIN_SECRET || "fallback-secret";

function sign(data) {
    return crypto.createHmac("sha256", SECRET).update(data).digest("hex").substring(0, 32);
}

export default async function handler(req, res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

    const hwid     = (req.query.hwid     || "").trim();
    const username = (req.query.username || "").trim();
    const userId   = (req.query.userId   || "").trim();

    if (!hwid || hwid === "undefined") return res.status(400).json({ error: "HWID wajib diisi" });
    if (hwid.length > 128)             return res.status(400).json({ error: "HWID tidak valid" });

    const ts      = Date.now();
    const payload = JSON.stringify({
        hwid:     hwid,
        username: username.substring(0, 64),
        userId:   userId.substring(0, 32),
        ts,
        exp: ts + 5 * 60 * 1000
    });

    const encoded = Buffer.from(payload).toString("base64url");
    const sig     = sign(encoded);

    return res.json({ url: `/getkey/?d=${encoded}&s=${sig}` });
}
