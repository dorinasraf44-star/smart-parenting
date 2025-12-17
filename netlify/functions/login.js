import { neon } from "@netlify/neon";
import crypto from "crypto";

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(test, "hex"));
}

export async function handler(event) {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let data;
  try { data = JSON.parse(event.body || "{}"); }
  catch { return json(400, { error: "Invalid JSON" }); }

  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";
  if (!email || !password) return json(400, { error: "Email + password required" });

  const sql = neon();

  try {
    const [user] = await sql`SELECT id, email, password_hash FROM users WHERE email = ${email};`;
    if (!user) return json(401, { error: "Invalid credentials" });

    if (!verifyPassword(password, user.password_hash)) {
      return json(401, { error: "Invalid credentials" });
    }

    const [session] = await sql`
      INSERT INTO sessions (user_id)
      VALUES (${user.id})
      RETURNING token, expires_at;
    `;

    return json(200, { ok: true, token: session.token, user: { id: user.id, email: user.email } });
  } catch (e) {
    return json(500, { error: "Server error", details: String(e?.message || e) });
  }
}
